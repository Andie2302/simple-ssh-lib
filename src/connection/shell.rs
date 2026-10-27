//! Interaktive Shell mit Pseudo-Terminal.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::Session;
use super::channel::{Channel, ExitStatus, open_session};
use super::mux::Event;
use crate::error::{Error, Result};

/// Terminal-Eigenschaften für `pty-req`.
#[derive(Debug, Clone)]
pub struct Pty {
    /// Wert für `$TERM`.
    pub term: String,
    pub cols: u32,
    pub rows: u32,
}

impl Pty {
    pub fn new(cols: u32, rows: u32) -> Self {
        Self {
            term: "xterm-256color".into(),
            cols,
            rows,
        }
    }
}

impl Default for Pty {
    fn default() -> Self {
        Self::new(80, 24)
    }
}

/// Laufende Shell. Lesen liefert die Terminal-Ausgabe (stdout und stderr sind im
/// Terminal vereint), Schreiben sendet Tastatureingaben. `shutdown` schickt EOF.
/// Wird die Shell fallen gelassen, wird der Channel geschlossen.
pub struct Shell {
    channel: Channel,
}

impl Session {
    /// Öffnet eine Shell mit Pseudo-Terminal.
    pub async fn shell(&self, pty: Pty) -> Result<Shell> {
        let channel = open_session(&self.handle).await?;
        let core = channel.core().clone();
        let accepted = core
            .request("pty-req", |w| {
                w.put_string(pty.term.as_bytes())
                    .put_u32(pty.cols)
                    .put_u32(pty.rows)
                    .put_u32(0)
                    .put_u32(0)
                    .put_string(&[0]); // Terminal-Modi: nur TTY_OP_END
            })
            .await?;
        if !accepted {
            return Err(Error::RequestRejected("pty-req"));
        }
        if !core.request("shell", |_| {}).await? {
            return Err(Error::RequestRejected("shell"));
        }
        Ok(Shell { channel })
    }
}

impl Shell {
    /// Teilt dem Server eine neue Terminalgröße mit.
    pub fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        self.channel.core().request_nowait("window-change", |w| {
            w.put_u32(cols).put_u32(rows).put_u32(0).put_u32(0);
        })
    }

    /// Bisher gemeldeter Exit-Status (`Unknown`, solange die Shell läuft).
    pub fn exit_status(&self) -> ExitStatus {
        self.channel.core().exit_status()
    }

    /// Wartet, bis der Server den Channel schließt, und liefert den Exit-Status.
    /// Noch nicht gelesene Ausgabe wird verworfen.
    pub async fn wait_exit(&mut self) -> Result<ExitStatus> {
        loop {
            match self.channel.reader.next_event().await {
                Some(Event::Close) => return Ok(self.exit_status()),
                Some(_) => {}
                None => return Err(self.channel.reader.lost_error()),
            }
        }
    }
}

impl AsyncRead for Shell {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.channel).poll_read(cx, buf)
    }
}

impl AsyncWrite for Shell {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.channel).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.channel).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.channel).poll_shutdown(cx)
    }
}
