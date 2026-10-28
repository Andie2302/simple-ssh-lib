//! Interaktive Shell mit Pseudo-Terminal.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::Session;
use super::channel::{
    Channel, ChannelCore, ChannelReader, ChannelWriter, ExitStatus, open_session,
};
use super::mux::Event;
use crate::error::{Error, Result};
use crate::wire::check_field;

/// Terminal-Eigenschaften für `pty-req`.
#[derive(Debug, Clone)]
pub struct Pty {
    /// Wert für `$TERM`.
    pub term: String,
    /// Spalten.
    pub cols: u32,
    /// Zeilen.
    pub rows: u32,
}

impl Pty {
    /// Terminal vom Typ `xterm-256color` in der angegebenen Größe.
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

impl std::fmt::Debug for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shell")
            .field("exit_status", &self.exit_status())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Öffnet eine Shell mit Pseudo-Terminal.
    pub async fn shell(&self, pty: Pty) -> Result<Shell> {
        check_field(&pty.term, "terminal name")?;
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

impl Shell {
    /// Teilt die Shell in Leseseite, Schreibseite und eine Steuerung.
    ///
    /// So können Ausgabe und Eingabe in getrennten Tasks laufen (kein Blockieren, wenn
    /// beide Richtungen gleichzeitig viel Daten haben), und die Terminalgröße lässt sich
    /// weiter ändern. Werden `ShellReader` und `ShellWriter` fallen gelassen, wird der
    /// Channel geschlossen; die `ShellControl` hält ihn nicht offen.
    pub fn split(self) -> (ShellReader, ShellWriter, ShellControl) {
        let Channel { reader, writer } = self.channel;
        let control = ShellControl {
            core: Arc::downgrade(&writer.core),
            exit: writer.core.exit_handle(),
        };
        (ShellReader { reader }, ShellWriter { writer }, control)
    }
}

/// Leseseite einer geteilten [`Shell`]: Terminalausgabe (`AsyncRead`).
pub struct ShellReader {
    reader: ChannelReader,
}

/// Schreibseite einer geteilten [`Shell`]: Tastatureingaben (`AsyncWrite`,
/// `shutdown` sendet EOF).
pub struct ShellWriter {
    writer: ChannelWriter,
}

/// Steuerung einer geteilten [`Shell`]: Terminalgröße ändern und Status abfragen.
/// Günstig zu klonen und aus jedem Task nutzbar.
#[derive(Clone)]
pub struct ShellControl {
    core: Weak<ChannelCore>,
    exit: Arc<Mutex<ExitStatus>>,
}

impl ShellControl {
    /// Teilt dem Server eine neue Terminalgröße mit. Nach dem Ende der Shell ein Fehler.
    pub fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        let core = self
            .core
            .upgrade()
            .ok_or_else(|| Error::ConnectionLost("shell channel closed".into()))?;
        core.request_nowait("window-change", |w| {
            w.put_u32(cols).put_u32(rows).put_u32(0).put_u32(0);
        })
    }

    /// Bisher gemeldeter Exit-Status (`Unknown`, solange die Shell läuft). Bleibt nach
    /// dem Ende der Shell abrufbar.
    pub fn exit_status(&self) -> ExitStatus {
        self.exit.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl ShellReader {
    /// Wartet, bis der Server den Channel schließt, und liefert den Exit-Status.
    /// Noch nicht gelesene Ausgabe wird verworfen. Verbindungsabbruch ergibt einen Fehler.
    pub async fn wait_exit(mut self) -> Result<ExitStatus> {
        loop {
            match self.reader.next_event().await {
                Some(Event::Close) => return Ok(self.reader.core.exit_status()),
                Some(_) => {}
                None => return Err(self.reader.lost_error()),
            }
        }
    }
}

impl AsyncRead for ShellReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for ShellWriter {
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

impl std::fmt::Debug for ShellReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShellReader").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ShellWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShellWriter").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ShellControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShellControl")
            .field("exit_status", &self.exit_status())
            .finish()
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
