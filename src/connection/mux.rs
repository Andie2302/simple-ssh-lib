//! Multiplexer: Ein Lese-Task verteilt eingehende Nachrichten auf Channels,
//! ein Schreib-Task sendet alles aus einer Warteschlange. Dadurch können mehrere
//! Channels gleichzeitig lesen und schreiben.
//!
//! Zustand (Fenster, Antworten auf Requests) liegt hinter einem `std::sync::Mutex`,
//! der nie über ein `await` gehalten wird.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::Waker;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use super::channel::ExitStatus;
use crate::error::{Error, Result};
use crate::transport::cipher::ChaChaPoly;
use crate::transport::rekey::{PendingKex, RekeyContext, is_kex_class};
use crate::transport::{MSG_NEWKEYS, RecvHalf, SendHalf, kexinit};
use crate::wire::{Reader, Writer};

pub(crate) const MSG_DISCONNECT: u8 = 1;
const MSG_GLOBAL_REQUEST: u8 = 80;
const MSG_REQUEST_FAILURE: u8 = 82;
pub(crate) const MSG_CHANNEL_OPEN: u8 = 90;
const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub(crate) const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub(crate) const MSG_CHANNEL_DATA: u8 = 94;
const MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub(crate) const MSG_CHANNEL_EOF: u8 = 96;
pub(crate) const MSG_CHANNEL_CLOSE: u8 = 97;
pub(crate) const MSG_CHANNEL_REQUEST: u8 = 98;
const MSG_CHANNEL_SUCCESS: u8 = 99;
const MSG_CHANNEL_FAILURE: u8 = 100;

const OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
const DISCONNECT_BY_APPLICATION: u32 = 11;

/// Empfangsfenster pro Channel (OpenSSH-Standard).
pub(crate) const WINDOW: u32 = 2 * 1024 * 1024;
/// Größte Datenmenge pro Paket, die wir annehmen und senden.
pub(crate) const MAX_PACKET: u32 = 32 * 1024;

/// Was ein Channel von der Gegenstelle erhält.
pub(crate) enum Event {
    Data(Vec<u8>),
    Stderr(Vec<u8>),
    Eof,
    Close,
}

pub(crate) struct Chan {
    pub remote: u32,
    /// Wie viel wir noch senden dürfen.
    pub send_window: u32,
    pub max_packet: u32,
    /// Wie viel der Server noch senden darf.
    pub recv_window: u32,
    pub events: mpsc::UnboundedSender<Event>,
    pub opening: Option<oneshot::Sender<Result<()>>>,
    /// Wartende Requests mit Antwort, in Reihenfolge.
    pub replies: VecDeque<oneshot::Sender<bool>>,
    pub write_waker: Option<Waker>,
    pub close_sent: bool,
    pub eof_sent: bool,
    pub exit: Arc<Mutex<ExitStatus>>,
}

pub(crate) struct State {
    pub channels: HashMap<u32, Chan>,
    pub next_id: u32,
    pub lost: Option<String>,
}

/// Eintrag der Sendewarteschlange. Nur der Schreib-Task schreibt auf den Draht, damit
/// die Reihenfolge und der Zeitpunkt des Schlüsselwechsels eindeutig bleiben.
pub(crate) enum Out {
    /// Normale Nachricht; während eines Schlüsselwechsels zurückgehalten (Typ >= 50).
    Packet(Vec<u8>),
    /// Nachricht des Schlüsselaustauschs; geht immer sofort raus.
    Kex(Vec<u8>),
    /// Ab hier bis `Install` keine Kanalnachrichten mehr senden.
    BeginKex,
    /// Neue Sendeschlüssel aktivieren (direkt nach dem NEWKEYS-Paket).
    Install(ChaChaPoly),
}

/// Wann wir selbst einen Schlüsselwechsel anstoßen.
#[derive(Clone, Copy)]
pub(crate) struct RekeyLimits {
    pub bytes: u64,
    pub interval: Duration,
}

/// So lange darf ein Schlüsselwechsel dauern, bevor die Verbindung als tot gilt.
const REKEY_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct Conn {
    out: mpsc::UnboundedSender<Out>,
    state: Mutex<State>,
    /// Unser KEXINIT, solange ein Schlüsselwechsel läuft. Wer es hier einträgt, sendet es.
    kex: Mutex<Option<Vec<u8>>>,
    /// Bytes (gesendet + empfangen) seit dem letzten Schlüsselwechsel.
    traffic: AtomicU64,
    /// Abgeschlossene Schlüsselwechsel nach dem ersten Handshake.
    rekeys: AtomicU64,
}

fn violation<T>(what: &'static str) -> Result<T> {
    Err(Error::ProtocolViolation(what))
}

impl Conn {
    fn new(out: mpsc::UnboundedSender<Out>) -> Self {
        Self {
            out,
            state: Mutex::new(State {
                channels: HashMap::new(),
                next_id: 0,
                lost: None,
            }),
            kex: Mutex::new(None),
            traffic: AtomicU64::new(0),
            rekeys: AtomicU64::new(0),
        }
    }

    fn kex_slot(&self) -> MutexGuard<'_, Option<Vec<u8>>> {
        self.kex.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reiht eine normale Nachricht ein. `Err`, wenn der Schreib-Task beendet ist.
    pub fn enqueue(&self, payload: Vec<u8>) -> std::result::Result<(), ()> {
        self.out.send(Out::Packet(payload)).map_err(|_| ())
    }

    fn enqueue_out(&self, item: Out) -> Result<()> {
        self.out.send(item).map_err(|_| self.lost_error())
    }

    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn lost_error(&self) -> Error {
        Error::ConnectionLost(
            self.lock()
                .lost
                .clone()
                .unwrap_or_else(|| "connection closed".into()),
        )
    }

    /// Stellt eine Nachricht in die Sendewarteschlange.
    pub fn send(&self, payload: Vec<u8>) -> Result<()> {
        self.enqueue(payload).map_err(|_| self.lost_error())
    }

    /// Markiert die Verbindung als verloren und weckt alle Wartenden.
    fn fail(&self, err: Error) {
        let chans: Vec<Chan> = {
            let mut st = self.lock();
            st.lost.get_or_insert_with(|| err.to_string());
            st.channels.drain().map(|(_, c)| c).collect()
        };
        for mut chan in chans {
            if let Some(w) = chan.write_waker.take() {
                w.wake();
            }
            // Der Drop von `events`, `opening` und `replies` weckt die Empfänger.
        }
    }

    fn send_simple(&self, kind: u8, remote: u32) -> Result<()> {
        let mut w = Writer::new();
        w.put_u8(kind).put_u32(remote);
        self.send(w.into_vec())
    }

    /// Verarbeitet eine Nachricht des Servers.
    fn dispatch(&self, msg: &[u8]) -> Result<()> {
        let kind = msg[0];
        let mut r = Reader::new(&msg[1..]);
        match kind {
            MSG_GLOBAL_REQUEST => {
                r.get_string()?; // z.B. hostkeys-00@openssh.com
                if r.get_bool()? {
                    self.send(vec![MSG_REQUEST_FAILURE])?;
                }
            }
            MSG_CHANNEL_OPEN => {
                // Vom Server geöffnete Channels (Forwarding, X11) unterstützen wir nicht.
                r.get_string()?;
                let sender = r.get_u32()?;
                let mut w = Writer::new();
                w.put_u8(MSG_CHANNEL_OPEN_FAILURE)
                    .put_u32(sender)
                    .put_u32(OPEN_ADMINISTRATIVELY_PROHIBITED)
                    .put_string(b"")
                    .put_string(b"");
                self.send(w.into_vec())?;
            }
            MSG_CHANNEL_OPEN_CONFIRMATION => {
                let local = r.get_u32()?;
                let remote = r.get_u32()?;
                let window = r.get_u32()?;
                let max_packet = r.get_u32()?;
                r.finish()?;
                let mut st = self.lock();
                match st.channels.get_mut(&local) {
                    Some(chan) => {
                        let Some(done) = chan.opening.take() else {
                            return violation("duplicate open confirmation");
                        };
                        chan.remote = remote;
                        chan.send_window = window;
                        chan.max_packet = max_packet.clamp(1, MAX_PACKET);
                        let _ = done.send(Ok(()));
                    }
                    None => {
                        // Öffnen wurde abgebrochen: Gegenseite wieder schließen.
                        drop(st);
                        self.send_simple(MSG_CHANNEL_CLOSE, remote)?;
                    }
                }
            }
            MSG_CHANNEL_OPEN_FAILURE => {
                let local = r.get_u32()?;
                let reason = r.get_u32()?;
                let message = String::from_utf8_lossy(r.get_string()?).into_owned();
                if let Some(chan) = self.lock().channels.remove(&local)
                    && let Some(done) = chan.opening
                {
                    let _ = done.send(Err(Error::ChannelOpenFailed { reason, message }));
                }
            }
            MSG_CHANNEL_CLOSE => {
                let local = r.get_u32()?;
                let removed = self.lock().channels.remove(&local);
                // Unbekannte Channels: Antwort auf ein abgebrochenes Öffnen, ignorieren.
                if let Some(mut chan) = removed {
                    if !chan.close_sent {
                        self.send_simple(MSG_CHANNEL_CLOSE, chan.remote)?;
                    }
                    let _ = chan.events.send(Event::Close);
                    if let Some(w) = chan.write_waker.take() {
                        w.wake();
                    }
                }
            }
            MSG_CHANNEL_WINDOW_ADJUST => {
                let local = r.get_u32()?;
                let add = r.get_u32()?;
                r.finish()?;
                let mut st = self.lock();
                let chan = st
                    .channels
                    .get_mut(&local)
                    .ok_or(Error::ProtocolViolation("unknown channel"))?;
                chan.send_window = chan
                    .send_window
                    .checked_add(add)
                    .ok_or(Error::ProtocolViolation("send window overflow"))?;
                if let Some(w) = chan.write_waker.take() {
                    w.wake();
                }
            }
            MSG_CHANNEL_DATA | MSG_CHANNEL_EXTENDED_DATA => {
                let local = r.get_u32()?;
                if kind == MSG_CHANNEL_EXTENDED_DATA {
                    r.get_u32()?; // Datentyp; nur 1 (stderr) ist definiert
                }
                let data = r.get_string()?;
                r.finish()?;
                if data.len() > MAX_PACKET as usize {
                    return violation("data packet larger than announced maximum");
                }
                let mut st = self.lock();
                let chan = st
                    .channels
                    .get_mut(&local)
                    .ok_or(Error::ProtocolViolation("unknown channel"))?;
                chan.recv_window = chan
                    .recv_window
                    .checked_sub(data.len() as u32)
                    .ok_or(Error::ProtocolViolation("peer exceeded receive window"))?;
                let event = if kind == MSG_CHANNEL_DATA {
                    Event::Data(data.to_vec())
                } else {
                    Event::Stderr(data.to_vec())
                };
                let _ = chan.events.send(event);
            }
            MSG_CHANNEL_EOF => {
                let local = r.get_u32()?;
                let mut st = self.lock();
                let chan = st
                    .channels
                    .get_mut(&local)
                    .ok_or(Error::ProtocolViolation("unknown channel"))?;
                let _ = chan.events.send(Event::Eof);
            }
            MSG_CHANNEL_REQUEST => {
                let local = r.get_u32()?;
                let name = r.get_string()?;
                let want_reply = r.get_bool()?;
                let mut reply_to = None;
                {
                    let mut st = self.lock();
                    let chan = st
                        .channels
                        .get_mut(&local)
                        .ok_or(Error::ProtocolViolation("unknown channel"))?;
                    let status = match name {
                        b"exit-status" => Some(ExitStatus::Code(r.get_u32()?)),
                        b"exit-signal" => Some(ExitStatus::Signal(
                            String::from_utf8_lossy(r.get_string()?).into_owned(),
                        )),
                        _ => None,
                    };
                    match status {
                        Some(s) => *chan.exit.lock().unwrap_or_else(|e| e.into_inner()) = s,
                        None if want_reply && !chan.close_sent => reply_to = Some(chan.remote),
                        None => {}
                    }
                }
                if let Some(remote) = reply_to {
                    self.send_simple(MSG_CHANNEL_FAILURE, remote)?;
                }
            }
            MSG_CHANNEL_SUCCESS | MSG_CHANNEL_FAILURE => {
                let local = r.get_u32()?;
                let mut st = self.lock();
                let chan = st
                    .channels
                    .get_mut(&local)
                    .ok_or(Error::ProtocolViolation("unknown channel"))?;
                let waiting = chan
                    .replies
                    .pop_front()
                    .ok_or(Error::ProtocolViolation("unexpected request reply"))?;
                let _ = waiting.send(kind == MSG_CHANNEL_SUCCESS);
            }
            _ => return violation("unexpected message"),
        }
        Ok(())
    }
}

/// Beendet beim letzten Drop die Verbindung höflich.
pub(crate) struct Guard {
    conn: Arc<Conn>,
    reader: AbortHandle,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let mut w = Writer::new();
        w.put_u8(MSG_DISCONNECT)
            .put_u32(DISCONNECT_BY_APPLICATION)
            .put_string(b"")
            .put_string(b"");
        let _ = self.conn.enqueue(w.into_vec());
        self.reader.abort();
    }
}

/// Gemeinsamer Zugriff auf die Verbindung; die letzte Kopie beendet sie.
#[derive(Clone)]
pub(crate) struct Handle {
    pub conn: Arc<Conn>,
    _guard: Arc<Guard>,
}

impl Handle {
    /// `true`, wenn die Verbindung abgebrochen ist.
    pub fn is_lost(&self) -> bool {
        self.conn.lock().lost.is_some()
    }

    /// Anzahl abgeschlossener Schlüsselwechsel seit dem ersten Handshake.
    pub fn rekey_count(&self) -> u64 {
        self.conn.rekeys.load(Ordering::Relaxed)
    }
}

/// Startet Lese- und Schreib-Task.
pub(crate) fn spawn<R, W>(
    recv: RecvHalf<R>,
    send: SendHalf<W>,
    context: RekeyContext,
    limits: RekeyLimits,
) -> Handle
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::unbounded_channel();
    let conn = Arc::new(Conn::new(tx));
    let reader = tokio::spawn(reader_task(recv, conn.clone(), context)).abort_handle();
    tokio::spawn(writer_task(
        send,
        rx,
        Arc::downgrade(&conn),
        reader.clone(),
        limits,
    ));
    Handle {
        conn: conn.clone(),
        _guard: Arc::new(Guard { conn, reader }),
    }
}

async fn reader_task<R: AsyncRead + Unpin>(
    mut recv: RecvHalf<R>,
    conn: Arc<Conn>,
    context: RekeyContext,
) {
    let err = loop {
        let msg = match recv.recv().await {
            Ok(msg) => msg,
            Err(e) => break e,
        };
        conn.traffic.fetch_add(msg.len() as u64, Ordering::Relaxed);
        let handled = if msg[0] == kexinit::MSG_KEXINIT {
            rekey(&mut recv, &conn, &context, msg).await
        } else {
            conn.dispatch(&msg)
        };
        if let Err(e) = handled {
            break e;
        }
    };
    conn.fail(err);
}

/// Schlüsselwechsel, ausgelöst durch das KEXINIT des Servers (`server_kexinit`).
/// Hat unsere Seite schon ein KEXINIT geschickt (Schwelle erreicht), wird es verwendet,
/// sonst schicken wir jetzt eines.
async fn rekey<R: AsyncRead + Unpin>(
    recv: &mut RecvHalf<R>,
    conn: &Conn,
    context: &RekeyContext,
    server_kexinit: Vec<u8>,
) -> Result<()> {
    let ours = {
        let mut slot = conn.kex_slot();
        match slot.as_ref() {
            Some(existing) => existing.clone(),
            None => {
                let ours = kexinit::build_client_kexinit(false)?;
                *slot = Some(ours.clone());
                conn.enqueue_out(Out::BeginKex)?;
                conn.enqueue_out(Out::Kex(ours.clone()))?;
                ours
            }
        }
    };

    let (pending, init_message) = PendingKex::begin(ours, server_kexinit)?;
    conn.enqueue_out(Out::Kex(init_message))?;
    let reply = recv.recv().await?;
    let keys = pending.finish(context, &reply)?;

    // NEWKEYS geht noch mit den alten Schlüsseln raus, danach schaltet der Schreib-Task um.
    conn.enqueue_out(Out::Kex(vec![MSG_NEWKEYS]))?;
    conn.enqueue_out(Out::Install(ChaChaPoly::new(&keys.client_to_server)))?;
    if recv.recv().await? != [MSG_NEWKEYS] {
        return Err(Error::ProtocolViolation("expected NEWKEYS"));
    }
    recv.install(ChaChaPoly::new(&keys.server_to_client));

    // Erst jetzt ist ein neuer Austausch wieder zulässig (nächstes KEXINIT, Schwelle).
    *conn.kex_slot() = None;
    conn.rekeys.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Zustand des Schreib-Tasks. Die Verbindung wird bewusst nur je Nachricht über ein
/// `Weak` gehalten: Der Task darf sie nicht am Leben halten, sonst endet er nie.
struct WriterState<W> {
    send: SendHalf<W>,
    limits: RekeyLimits,
    /// Ein Schlüsselwechsel läuft: Kanalnachrichten zurückhalten.
    holding: bool,
    deferred: VecDeque<Vec<u8>>,
    hold_deadline: Option<Instant>,
    last_kex: Instant,
}

impl<W: AsyncWrite + Unpin> WriterState<W> {
    async fn write(&mut self, conn: &Conn, payload: &[u8]) -> Result<()> {
        self.send.send(payload).await?;
        conn.traffic
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    async fn handle(&mut self, conn: &Conn, item: Out) -> Result<()> {
        match item {
            Out::BeginKex => {
                self.holding = true;
                self.hold_deadline
                    .get_or_insert(Instant::now() + REKEY_TIMEOUT);
            }
            Out::Kex(payload) => self.write(conn, &payload).await?,
            Out::Install(cipher) => {
                self.send.install(cipher);
                self.holding = false;
                self.hold_deadline = None;
                self.last_kex = Instant::now();
                conn.traffic.store(0, Ordering::Relaxed);
                // Der Rückstau läuft wieder durch die normale Prüfung, damit auch hier
                // die Schwelle gilt und bei Bedarf gleich der nächste Wechsel beginnt.
                let backlog = std::mem::take(&mut self.deferred);
                for payload in backlog {
                    self.packet(conn, payload).await?;
                }
            }
            Out::Packet(payload) => self.packet(conn, payload).await?,
        }
        Ok(())
    }

    async fn packet(&mut self, conn: &Conn, payload: Vec<u8>) -> Result<()> {
        let held_back = !is_kex_class(payload[0]);
        if held_back && self.holding {
            self.deferred.push_back(payload);
            return Ok(());
        }
        if held_back && self.rekey_due(conn) {
            // Wer den Platz belegt, sendet das KEXINIT. Ist er schon belegt, hat der
            // Leser einen Wechsel begonnen und BeginKex folgt.
            let started = {
                let mut slot = conn.kex_slot();
                if slot.is_none() {
                    let ours = kexinit::build_client_kexinit(false)?;
                    *slot = Some(ours.clone());
                    Some(ours)
                } else {
                    None
                }
            };
            if let Some(ours) = started {
                self.write(conn, &ours).await?;
                self.holding = true;
                self.hold_deadline = Some(Instant::now() + REKEY_TIMEOUT);
                self.deferred.push_back(payload);
                return Ok(());
            }
        }
        self.write(conn, &payload).await
    }

    fn rekey_due(&self, conn: &Conn) -> bool {
        conn.traffic.load(Ordering::Relaxed) >= self.limits.bytes
            || self.last_kex.elapsed() >= self.limits.interval
    }
}

async fn writer_task<W: AsyncWrite + Unpin>(
    send: SendHalf<W>,
    mut queue: mpsc::UnboundedReceiver<Out>,
    conn: Weak<Conn>,
    reader: AbortHandle,
    limits: RekeyLimits,
) {
    let mut state = WriterState {
        send,
        limits,
        holding: false,
        deferred: VecDeque::new(),
        hold_deadline: None,
        last_kex: Instant::now(),
    };

    loop {
        let item = match state.hold_deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline.into(), queue.recv()).await {
                Ok(item) => item,
                Err(_) => {
                    if let Some(conn) = conn.upgrade() {
                        conn.fail(Error::ConnectionLost("key re-exchange timed out".into()));
                    }
                    reader.abort();
                    return;
                }
            },
            None => queue.recv().await,
        };
        let Some(item) = item else { return };
        let Some(conn) = conn.upgrade() else { return };
        if let Err(e) = state.handle(&conn, item).await {
            conn.fail(e);
            reader.abort();
            return;
        }
    }
}
