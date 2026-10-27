//! Multiplexer: Ein Lese-Task verteilt eingehende Nachrichten auf Channels,
//! ein Schreib-Task sendet alles aus einer Warteschlange. Dadurch können mehrere
//! Channels gleichzeitig lesen und schreiben.
//!
//! Zustand (Fenster, Antworten auf Requests) liegt hinter einem `std::sync::Mutex`,
//! der nie über ein `await` gehalten wird.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::Waker;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use super::channel::ExitStatus;
use crate::error::{Error, Result};
use crate::transport::{RecvHalf, SendHalf};
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

pub(crate) struct Conn {
    pub out: mpsc::UnboundedSender<Vec<u8>>,
    state: Mutex<State>,
}

fn violation<T>(what: &'static str) -> Result<T> {
    Err(Error::ProtocolViolation(what))
}

impl Conn {
    fn new(out: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self {
            out,
            state: Mutex::new(State {
                channels: HashMap::new(),
                next_id: 0,
                lost: None,
            }),
        }
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
        self.out.send(payload).map_err(|_| self.lost_error())
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
        let _ = self.conn.out.send(w.into_vec());
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
}

/// Startet Lese- und Schreib-Task.
pub(crate) fn spawn<R, W>(recv: RecvHalf<R>, send: SendHalf<W>) -> Handle
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::unbounded_channel();
    let conn = Arc::new(Conn::new(tx));
    let reader = tokio::spawn(reader_task(recv, conn.clone())).abort_handle();
    tokio::spawn(writer_task(send, rx, Arc::downgrade(&conn), reader.clone()));
    Handle {
        conn: conn.clone(),
        _guard: Arc::new(Guard { conn, reader }),
    }
}

async fn reader_task<R: AsyncRead + Unpin>(mut recv: RecvHalf<R>, conn: Arc<Conn>) {
    let err = loop {
        match recv.recv().await {
            Ok(msg) => {
                if let Err(e) = conn.dispatch(&msg) {
                    break e;
                }
            }
            Err(e) => break e,
        }
    };
    conn.fail(err);
}

async fn writer_task<W: AsyncWrite + Unpin>(
    mut send: SendHalf<W>,
    mut queue: mpsc::UnboundedReceiver<Vec<u8>>,
    conn: Weak<Conn>,
    reader: AbortHandle,
) {
    while let Some(payload) = queue.recv().await {
        if let Err(e) = send.send(&payload).await {
            if let Some(conn) = conn.upgrade() {
                conn.fail(e);
            }
            reader.abort();
            return;
        }
    }
}
