//! Ein Session-Channel: Lese- und Schreibseite mit Flow-Control.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use super::mux::{
    Chan, Event, Handle, MAX_PACKET, MSG_CHANNEL_CLOSE, MSG_CHANNEL_DATA, MSG_CHANNEL_EOF,
    MSG_CHANNEL_OPEN, MSG_CHANNEL_REQUEST, MSG_CHANNEL_WINDOW_ADJUST, WINDOW,
};
use crate::error::{Error, Result};
use crate::wire::Writer;

/// Wie ein Befehl oder eine Shell beendet wurde.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitStatus {
    /// Normales Ende mit diesem Exit-Code.
    Code(u32),
    /// Durch ein Signal beendet (Name ohne `SIG`, z.B. `KILL`).
    Signal(String),
    /// Der Server hat keinen Status gemeldet.
    Unknown,
}

fn io_error(err: Error) -> io::Error {
    let kind = match err {
        Error::ConnectionLost(_) => io::ErrorKind::ConnectionAborted,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, err.to_string())
}

/// Gemeinsamer Teil von Lese- und Schreibseite. Der letzte Drop schließt den Channel.
pub(crate) struct ChannelCore {
    id: u32,
    handle: Handle,
    exit: Arc<Mutex<ExitStatus>>,
}

impl ChannelCore {
    pub fn exit_status(&self) -> ExitStatus {
        self.exit.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Gemeinsamer Status-Zähler, der auch nach dem Schließen des Channels lesbar bleibt.
    pub fn exit_handle(&self) -> Arc<Mutex<ExitStatus>> {
        self.exit.clone()
    }

    /// Sendet CHANNEL_CLOSE, falls das noch nicht geschehen ist.
    pub fn close(&self) {
        let remote = {
            let mut st = self.handle.conn.lock();
            match st.channels.get_mut(&self.id) {
                Some(chan) if !chan.close_sent => {
                    chan.close_sent = true;
                    chan.remote
                }
                _ => return,
            }
        };
        let mut w = Writer::new();
        w.put_u8(MSG_CHANNEL_CLOSE).put_u32(remote);
        let _ = self.handle.conn.send(w.into_vec());
    }

    fn request_message(
        &self,
        name: &str,
        want_reply: bool,
        fill: impl FnOnce(&mut Writer),
    ) -> Result<Vec<u8>> {
        let st = self.handle.conn.lock();
        if let Some(reason) = &st.lost {
            return Err(Error::ConnectionLost(reason.clone()));
        }
        let chan = st
            .channels
            .get(&self.id)
            .filter(|c| !c.close_sent)
            .ok_or_else(|| Error::ConnectionLost("channel closed".into()))?;
        let mut w = Writer::new();
        w.put_u8(MSG_CHANNEL_REQUEST)
            .put_u32(chan.remote)
            .put_string(name.as_bytes())
            .put_bool(want_reply);
        fill(&mut w);
        Ok(w.into_vec())
    }

    /// Sendet einen Request und wartet auf die Antwort des Servers (`true` = Erfolg).
    pub async fn request(&self, name: &str, fill: impl FnOnce(&mut Writer)) -> Result<bool> {
        let msg = self.request_message(name, true, fill)?;
        let (tx, rx) = oneshot::channel();
        {
            let mut st = self.handle.conn.lock();
            let chan = st
                .channels
                .get_mut(&self.id)
                .ok_or_else(|| self.handle.conn.lost_error())?;
            chan.replies.push_back(tx);
        }
        self.handle.conn.send(msg)?;
        rx.await.map_err(|_| self.handle.conn.lost_error())
    }

    /// Sendet einen Request ohne Antwort (z.B. `window-change`).
    pub fn request_nowait(&self, name: &str, fill: impl FnOnce(&mut Writer)) -> Result<()> {
        let msg = self.request_message(name, false, fill)?;
        self.handle.conn.send(msg)
    }
}

impl Drop for ChannelCore {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) struct Channel {
    pub reader: ChannelReader,
    pub writer: ChannelWriter,
}

impl Channel {
    pub fn core(&self) -> &Arc<ChannelCore> {
        &self.writer.core
    }
}

/// Entfernt einen halb geöffneten Channel wieder, falls das Öffnen abgebrochen wird.
struct OpenGuard<'a> {
    handle: &'a Handle,
    id: u32,
    armed: bool,
}

impl Drop for OpenGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.handle.conn.lock().channels.remove(&self.id);
        }
    }
}

/// Öffnet einen `session`-Channel.
pub(crate) async fn open_session(handle: &Handle) -> Result<Channel> {
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let (opened_tx, opened_rx) = oneshot::channel();
    let exit = Arc::new(Mutex::new(ExitStatus::Unknown));
    let id = {
        let mut st = handle.conn.lock();
        if let Some(reason) = &st.lost {
            return Err(Error::ConnectionLost(reason.clone()));
        }
        let id = st.next_id;
        st.next_id += 1;
        st.channels.insert(
            id,
            Chan {
                remote: 0,
                send_window: 0,
                max_packet: 1,
                recv_window: WINDOW,
                events: events_tx,
                opening: Some(opened_tx),
                replies: VecDeque::new(),
                write_waker: None,
                close_sent: false,
                eof_sent: false,
                exit: exit.clone(),
            },
        );
        id
    };
    let mut guard = OpenGuard {
        handle,
        id,
        armed: true,
    };

    let mut w = Writer::new();
    w.put_u8(MSG_CHANNEL_OPEN)
        .put_string(b"session")
        .put_u32(id)
        .put_u32(WINDOW)
        .put_u32(MAX_PACKET);
    handle.conn.send(w.into_vec())?;

    match opened_rx.await {
        Ok(Ok(())) => guard.armed = false,
        Ok(Err(e)) => {
            guard.armed = false; // schon entfernt
            return Err(e);
        }
        Err(_) => return Err(handle.conn.lost_error()),
    }

    let core = Arc::new(ChannelCore {
        id,
        handle: handle.clone(),
        exit,
    });
    Ok(Channel {
        reader: ChannelReader {
            core: core.clone(),
            events: events_rx,
            buf: Vec::new(),
            pos: 0,
            unacked: 0,
            finished: false,
            closed_cleanly: false,
        },
        writer: ChannelWriter { core },
    })
}

pub(crate) struct ChannelReader {
    pub(crate) core: Arc<ChannelCore>,
    events: mpsc::UnboundedReceiver<Event>,
    buf: Vec<u8>,
    pos: usize,
    /// Verarbeitete, dem Server noch nicht gutgeschriebene Bytes.
    unacked: u32,
    finished: bool,
    closed_cleanly: bool,
}

impl ChannelReader {
    fn consumed(&mut self, n: usize) {
        self.unacked = self.unacked.saturating_add(n as u32);
        if self.unacked < WINDOW / 2 {
            return;
        }
        let remote = {
            let mut st = self.core.handle.conn.lock();
            match st.channels.get_mut(&self.core.id) {
                Some(chan) if !chan.close_sent => {
                    chan.recv_window += self.unacked;
                    chan.remote
                }
                _ => return,
            }
        };
        let mut w = Writer::new();
        w.put_u8(MSG_CHANNEL_WINDOW_ADJUST)
            .put_u32(remote)
            .put_u32(self.unacked);
        let _ = self.core.handle.conn.send(w.into_vec());
        self.unacked = 0;
    }

    pub(crate) fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<Option<Event>> {
        if self.finished {
            return Poll::Ready(None);
        }
        match self.events.poll_recv(cx) {
            Poll::Ready(Some(event)) => {
                match &event {
                    Event::Data(d) | Event::Stderr(d) => self.consumed(d.len()),
                    Event::Close => {
                        self.finished = true;
                        self.closed_cleanly = true;
                    }
                    Event::Eof => {}
                }
                Poll::Ready(Some(event))
            }
            Poll::Ready(None) => {
                self.finished = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Nächstes Ereignis; `None`, wenn die Verbindung abgebrochen ist.
    pub(crate) async fn next_event(&mut self) -> Option<Event> {
        std::future::poll_fn(|cx| self.poll_event(cx)).await
    }

    pub(crate) fn lost_error(&self) -> Error {
        self.core.handle.conn.lost_error()
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.pos < self.buf.len() {
                let n = (self.buf.len() - self.pos).min(out.remaining());
                let start = self.pos;
                out.put_slice(&self.buf[start..start + n]);
                self.pos += n;
                return Poll::Ready(Ok(()));
            }
            match ready!(self.poll_event(cx)) {
                Some(Event::Data(d)) => {
                    self.buf = d;
                    self.pos = 0;
                }
                Some(Event::Stderr(_)) => {}
                // EOF der Ausgabe: ohne Daten zurückkehren = Ende des Streams.
                Some(Event::Eof) | Some(Event::Close) => return Poll::Ready(Ok(())),
                None if self.closed_cleanly => return Poll::Ready(Ok(())),
                None => return Poll::Ready(Err(io_error(self.lost_error()))),
            }
        }
    }
}

pub(crate) struct ChannelWriter {
    pub(crate) core: Arc<ChannelCore>,
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let conn = &self.core.handle.conn;
        let mut st = conn.lock();
        if let Some(reason) = &st.lost {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                reason.clone(),
            )));
        }
        let Some(chan) = st.channels.get_mut(&self.core.id) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "channel closed",
            )));
        };
        if chan.eof_sent || chan.close_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "channel closed for writing",
            )));
        }
        if chan.send_window == 0 {
            chan.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf
            .len()
            .min(chan.send_window as usize)
            .min(chan.max_packet as usize);
        chan.send_window -= n as u32;
        let mut w = Writer::new();
        w.put_u8(MSG_CHANNEL_DATA)
            .put_u32(chan.remote)
            .put_string(&buf[..n]);
        conn.enqueue(w.into_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Sendet EOF (schließt die Eingabe des Befehls).
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let conn = &self.core.handle.conn;
        let remote = {
            let mut st = conn.lock();
            match st.channels.get_mut(&self.core.id) {
                Some(chan) if !chan.eof_sent && !chan.close_sent => {
                    chan.eof_sent = true;
                    chan.remote
                }
                _ => return Poll::Ready(Ok(())),
            }
        };
        let mut w = Writer::new();
        w.put_u8(MSG_CHANNEL_EOF).put_u32(remote);
        let _ = conn.send(w.into_vec());
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Channel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for Channel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
