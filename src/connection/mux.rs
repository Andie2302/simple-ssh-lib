//! Multiplexer: Ein Lese-Task verteilt eingehende Nachrichten auf Channels,
//! ein Schreib-Task sendet alles aus einer Warteschlange. Dadurch können mehrere
//! Channels gleichzeitig lesen und schreiben.
//!
//! Zustand (Fenster, Antworten auf Requests) liegt hinter einem `std::sync::Mutex`,
//! der nie über ein `await` gehalten wird.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
const MSG_REQUEST_SUCCESS: u8 = 81;
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

/// Lebenszeichen-Prüfung: alle `interval` eine Anfrage; nach `max_missed` Intervallen
/// ohne irgendein empfangenes Paket gilt die Verbindung als tot.
#[derive(Clone, Copy)]
pub(crate) struct Keepalive {
    pub interval: Duration,
    pub max_missed: u32,
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
    /// Keepalive-Intervalle seit dem letzten empfangenen Paket.
    missed: AtomicU32,
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
            missed: AtomicU32::new(0),
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
            // Antworten auf unsere Keepalive-Anfragen; wichtig ist nur, dass etwas ankommt.
            MSG_REQUEST_SUCCESS | MSG_REQUEST_FAILURE => {}
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
    keepalive: Option<AbortHandle>,
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
        if let Some(keepalive) = &self.keepalive {
            keepalive.abort();
        }
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
    keepalive: Option<Keepalive>,
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
    let keepalive = keepalive.map(|k| {
        tokio::spawn(keepalive_task(Arc::downgrade(&conn), reader.clone(), k)).abort_handle()
    });
    Handle {
        conn: conn.clone(),
        _guard: Arc::new(Guard {
            conn,
            reader,
            keepalive,
        }),
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
        conn.missed.store(0, Ordering::Relaxed);
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

async fn keepalive_task(conn: Weak<Conn>, reader: AbortHandle, keepalive: Keepalive) {
    let mut ticker = tokio::time::interval(keepalive.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // der erste Tick kommt sofort
    loop {
        ticker.tick().await;
        let Some(conn) = conn.upgrade() else { return };
        if conn.lock().lost.is_some() {
            return;
        }
        if conn.missed.fetch_add(1, Ordering::Relaxed) >= keepalive.max_missed {
            conn.fail(Error::ConnectionLost("keepalive timeout".into()));
            reader.abort();
            return;
        }
        let mut w = Writer::new();
        w.put_u8(MSG_GLOBAL_REQUEST)
            .put_string(b"keepalive@openssh.com")
            .put_bool(true);
        if conn.enqueue(w.into_vec()).is_err() {
            return;
        }
    }
}

/// Einstiegspunkt für Robustheitstests: legt Kanal 0 an und verarbeitet `msg`.
#[doc(hidden)]
pub(crate) fn fuzz_dispatch(msg: &[u8]) {
    if msg.is_empty() {
        return;
    }
    let (conn, _out) = test_support::conn_with_channel();
    let _ = conn.dispatch(msg);
}

pub(crate) mod test_support {
    use super::*;

    /// Verbindung mit einem geöffneten Kanal 0 (entfernte Nummer 7) und dem
    /// Empfänger der Sendewarteschlange.
    pub fn conn_with_channel() -> (Arc<Conn>, mpsc::UnboundedReceiver<Out>) {
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let conn = Arc::new(Conn::new(out_tx));
        let (events, events_rx) = mpsc::unbounded_channel();
        std::mem::forget(events_rx); // Ereignisse werden hier nicht gelesen
        conn.lock().channels.insert(
            0,
            Chan {
                remote: 7,
                send_window: 100,
                max_packet: 1000,
                recv_window: 50,
                events,
                opening: None,
                replies: VecDeque::new(),
                write_waker: None,
                close_sent: false,
                eof_sent: false,
                exit: Arc::new(Mutex::new(ExitStatus::Unknown)),
            },
        );
        (conn, out_rx)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::conn_with_channel;
    use super::*;

    fn msg(kind: u8, fill: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_u8(kind);
        fill(&mut w);
        w.into_vec()
    }

    /// Alles, was bisher zum Senden eingereiht wurde.
    fn queued(rx: &mut mpsc::UnboundedReceiver<Out>) -> Vec<Vec<u8>> {
        let mut sent = Vec::new();
        while let Ok(item) = rx.try_recv() {
            if let Out::Packet(p) = item {
                sent.push(p);
            }
        }
        sent
    }

    fn is_violation(r: Result<()>) -> bool {
        matches!(r, Err(Error::ProtocolViolation(_)))
    }

    #[test]
    fn data_may_fill_the_window_but_never_exceed_it() {
        let (conn, _out) = conn_with_channel(); // Fenster: 50
        let data = |n: usize| {
            msg(MSG_CHANNEL_DATA, |w| {
                w.put_u32(0).put_string(&vec![1u8; n]);
            })
        };
        assert!(conn.dispatch(&data(50)).is_ok());
        assert!(is_violation(conn.dispatch(&data(1))));
    }

    #[test]
    fn oversized_data_packet_is_rejected_even_with_window_left() {
        let (conn, _out) = conn_with_channel();
        conn.lock().channels.get_mut(&0).unwrap().recv_window = u32::MAX;
        let big = msg(MSG_CHANNEL_DATA, |w| {
            w.put_u32(0).put_string(&vec![0u8; MAX_PACKET as usize + 1]);
        });
        assert!(is_violation(conn.dispatch(&big)));
    }

    #[test]
    fn send_window_overflow_is_rejected() {
        let (conn, _out) = conn_with_channel();
        conn.lock().channels.get_mut(&0).unwrap().send_window = u32::MAX - 5;
        let adjust = |n: u32| {
            msg(MSG_CHANNEL_WINDOW_ADJUST, |w| {
                w.put_u32(0).put_u32(n);
            })
        };
        assert!(conn.dispatch(&adjust(5)).is_ok());
        assert_eq!(conn.lock().channels[&0].send_window, u32::MAX);
        assert!(is_violation(conn.dispatch(&adjust(1))));
    }

    #[test]
    fn messages_for_unknown_channels_are_violations_except_close() {
        let (conn, mut out) = conn_with_channel();
        let for_unknown_channel = [
            msg(MSG_CHANNEL_DATA, |w| {
                w.put_u32(99).put_string(b"x");
            }),
            msg(MSG_CHANNEL_EXTENDED_DATA, |w| {
                w.put_u32(99).put_u32(1).put_string(b"x");
            }),
            msg(MSG_CHANNEL_EOF, |w| {
                w.put_u32(99);
            }),
            msg(MSG_CHANNEL_WINDOW_ADJUST, |w| {
                w.put_u32(99).put_u32(5);
            }),
            msg(MSG_CHANNEL_SUCCESS, |w| {
                w.put_u32(99);
            }),
            msg(MSG_CHANNEL_FAILURE, |w| {
                w.put_u32(99);
            }),
        ];
        for m in &for_unknown_channel {
            assert!(is_violation(conn.dispatch(m)), "type {}", m[0]);
        }
        let request = msg(MSG_CHANNEL_REQUEST, |w| {
            w.put_u32(99).put_string(b"x").put_bool(false);
        });
        assert!(is_violation(conn.dispatch(&request)));
        // CLOSE für einen unbekannten Kanal ist die Antwort auf ein abgebrochenes Öffnen.
        let close = msg(MSG_CHANNEL_CLOSE, |w| {
            w.put_u32(99);
        });
        assert!(conn.dispatch(&close).is_ok());
        assert!(queued(&mut out).is_empty());
    }

    #[test]
    fn confirmation_for_a_cancelled_open_closes_the_remote_channel() {
        let (conn, mut out) = conn_with_channel();
        let confirm = msg(MSG_CHANNEL_OPEN_CONFIRMATION, |w| {
            w.put_u32(55).put_u32(9).put_u32(1000).put_u32(1000);
        });
        assert!(conn.dispatch(&confirm).is_ok());
        let sent = queued(&mut out);
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0],
            msg(MSG_CHANNEL_CLOSE, |w| {
                w.put_u32(9);
            })
        );
    }

    #[test]
    fn duplicate_confirmation_and_unsolicited_replies_are_violations() {
        let (conn, _out) = conn_with_channel(); // Kanal 0 ist schon offen
        let confirm = msg(MSG_CHANNEL_OPEN_CONFIRMATION, |w| {
            w.put_u32(0).put_u32(9).put_u32(1000).put_u32(1000);
        });
        assert!(is_violation(conn.dispatch(&confirm)));
        let success = msg(MSG_CHANNEL_SUCCESS, |w| {
            w.put_u32(0);
        });
        assert!(is_violation(conn.dispatch(&success)));
    }

    #[test]
    fn request_replies_arrive_in_order() {
        let (conn, _out) = conn_with_channel();
        let (a_tx, mut a_rx) = oneshot::channel();
        let (b_tx, mut b_rx) = oneshot::channel();
        {
            let mut st = conn.lock();
            let chan = st.channels.get_mut(&0).unwrap();
            chan.replies.push_back(a_tx);
            chan.replies.push_back(b_tx);
        }
        let reply = |kind| {
            msg(kind, |w| {
                w.put_u32(0);
            })
        };
        conn.dispatch(&reply(MSG_CHANNEL_SUCCESS)).unwrap();
        conn.dispatch(&reply(MSG_CHANNEL_FAILURE)).unwrap();
        assert_eq!(a_rx.try_recv().ok(), Some(true));
        assert_eq!(b_rx.try_recv().ok(), Some(false));
    }

    #[test]
    fn global_requests_are_answered_only_when_a_reply_is_wanted() {
        let (conn, mut out) = conn_with_channel();
        let global = |want| {
            msg(MSG_GLOBAL_REQUEST, |w| {
                w.put_string(b"hostkeys-00@openssh.com").put_bool(want);
            })
        };
        conn.dispatch(&global(false)).unwrap();
        assert!(queued(&mut out).is_empty());
        conn.dispatch(&global(true)).unwrap();
        assert_eq!(queued(&mut out), vec![vec![MSG_REQUEST_FAILURE]]);
    }

    #[test]
    fn channels_opened_by_the_server_are_refused() {
        let (conn, mut out) = conn_with_channel();
        let open = msg(MSG_CHANNEL_OPEN, |w| {
            w.put_string(b"forwarded-tcpip")
                .put_u32(41)
                .put_u32(1000)
                .put_u32(1000);
        });
        conn.dispatch(&open).unwrap();
        let sent = queued(&mut out);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0][0], MSG_CHANNEL_OPEN_FAILURE);
        assert_eq!(&sent[0][1..5], &41u32.to_be_bytes());
    }

    #[test]
    fn exit_status_is_recorded_and_unknown_requests_are_refused() {
        let (conn, mut out) = conn_with_channel();
        let exit = msg(MSG_CHANNEL_REQUEST, |w| {
            w.put_u32(0)
                .put_string(b"exit-status")
                .put_bool(false)
                .put_u32(3);
        });
        conn.dispatch(&exit).unwrap();
        let status = conn.lock().channels[&0].exit.lock().unwrap().clone();
        assert_eq!(status, ExitStatus::Code(3));

        let unknown = msg(MSG_CHANNEL_REQUEST, |w| {
            w.put_u32(0).put_string(b"surprise").put_bool(true);
        });
        conn.dispatch(&unknown).unwrap();
        let sent = queued(&mut out);
        assert_eq!(
            sent,
            vec![msg(MSG_CHANNEL_FAILURE, |w| {
                w.put_u32(7);
            })]
        );
    }

    #[test]
    fn close_removes_the_channel_and_answers_exactly_once() {
        let (conn, mut out) = conn_with_channel();
        let close = msg(MSG_CHANNEL_CLOSE, |w| {
            w.put_u32(0);
        });
        conn.dispatch(&close).unwrap();
        assert!(conn.lock().channels.is_empty());
        assert_eq!(queued(&mut out).len(), 1);

        // Haben wir schon geschlossen, antworten wir nicht noch einmal.
        let (conn, mut out) = conn_with_channel();
        conn.lock().channels.get_mut(&0).unwrap().close_sent = true;
        conn.dispatch(&close).unwrap();
        assert!(queued(&mut out).is_empty());
    }

    #[test]
    fn truncated_and_unknown_messages_never_panic() {
        for kind in 0..=255u8 {
            for body_len in [0usize, 1, 3, 4, 5, 9, 12] {
                let (conn, _out) = conn_with_channel();
                let mut m = vec![kind];
                m.extend(std::iter::repeat_n(0u8, body_len));
                let _ = conn.dispatch(&m);
            }
        }
        let (conn, _out) = conn_with_channel();
        assert!(is_violation(conn.dispatch(&[200])));
    }

    #[test]
    fn failing_the_connection_wakes_everyone_and_blocks_new_work() {
        let (conn, _out) = conn_with_channel();
        let (tx, mut rx) = oneshot::channel::<bool>();
        conn.lock()
            .channels
            .get_mut(&0)
            .unwrap()
            .replies
            .push_back(tx);
        conn.fail(Error::ConnectionLost("boom".into()));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert!(conn.lock().channels.is_empty());
        assert!(
            matches!(conn.lost_error(), Error::ConnectionLost(m) if m == "connection lost: boom" || m.contains("boom"))
        );
    }
}
