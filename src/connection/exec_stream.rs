//! `exec_stream`: einen Befehl starten und Ausgabe und Eingabe als Strom behandeln.
//!
//! Anders als [`Session::exec`] wartet das nicht auf das Ende des Befehls: Ausgabe
//! und Fehlerausgabe kommen, sobald der Server sie schickt, und Eingabe kann jederzeit
//! gesendet werden. Ein langsamer Leser bremst den Server (Flow-Control); der Speicher
//! bleibt auf etwa ein Empfangsfenster (2 MiB) begrenzt.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

use super::Session;
use super::channel::{ChannelReader, ChannelWriter, ExitStatus, open_session};
use super::mux::Event;
use crate::error::{Error, Result};
use crate::wire::check_field;

/// Ein Stück Ausgabe eines laufenden Befehls.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExecEvent {
    /// Daten auf stdout.
    Stdout(Vec<u8>),
    /// Daten auf stderr.
    Stderr(Vec<u8>),
}

/// Ein laufender Befehl mit Eingabe und Ausgabe als Strom.
///
/// Mit [`ExecStream::split`] lassen sich Eingabe und Ausgabe getrennt (z.B. in zwei
/// Tasks) benutzen. Werden beide Hälften fallen gelassen, wird der Channel geschlossen.
pub struct ExecStream {
    stdin: ExecStdin,
    events: ExecEvents,
}

/// Eingabe (stdin) eines laufenden Befehls. Schreiben respektiert die Flow-Control des
/// Servers; [`shutdown`](tokio::io::AsyncWriteExt::shutdown) sendet EOF.
///
/// Wird nur diese Hälfte fallen gelassen, sieht der Befehl **kein** EOF – dafür ist
/// ausdrücklich `shutdown` aufzurufen.
pub struct ExecStdin {
    writer: ChannelWriter,
}

/// Ausgabe eines laufenden Befehls.
pub struct ExecEvents {
    reader: ChannelReader,
    done: bool,
}

impl Session {
    /// Startet `command` und gibt Eingabe und Ausgabe als Strom zurück.
    ///
    /// Der Befehl sieht stdin offen, bis [`ExecStdin`] mit `shutdown` geschlossen wird.
    /// Will der Befehl nichts lesen, schließe stdin sofort.
    pub async fn exec_stream(&self, command: &str) -> Result<ExecStream> {
        check_field(command, "command")?;
        let channel = open_session(&self.handle).await?;
        let accepted = channel
            .core()
            .request("exec", |w| {
                w.put_string(command.as_bytes());
            })
            .await?;
        if !accepted {
            return Err(Error::CommandRejected);
        }
        let super::channel::Channel { reader, writer } = channel;
        Ok(ExecStream {
            stdin: ExecStdin { writer },
            events: ExecEvents {
                reader,
                done: false,
            },
        })
    }
}

impl ExecStream {
    /// Teilt in Eingabe und Ausgabe.
    pub fn split(self) -> (ExecStdin, ExecEvents) {
        (self.stdin, self.events)
    }

    /// Nächstes Stück Ausgabe; siehe [`ExecEvents::next`].
    pub async fn next(&mut self) -> Result<Option<ExecEvent>> {
        self.events.next().await
    }

    /// Sendet `data` an stdin (wartet bei Bedarf auf Platz im Fenster des Servers).
    pub async fn write_stdin(&mut self, data: &[u8]) -> Result<()> {
        self.stdin.write_all(data).await.map_err(Error::Io)
    }

    /// Schließt stdin (EOF).
    pub async fn close_stdin(&mut self) -> Result<()> {
        self.stdin.shutdown().await.map_err(Error::Io)
    }

    /// Wie der Befehl endete; erst gültig, nachdem [`ExecStream::next`] `Ok(None)` lieferte.
    pub fn exit_status(&self) -> ExitStatus {
        self.events.exit_status()
    }
}

impl ExecEvents {
    /// Nächstes Stück Ausgabe.
    ///
    /// * `Ok(Some(..))`: Daten (die Ereignisse behalten die Reihenfolge je Strom).
    /// * `Ok(None)`: Der Befehl ist beendet und der Channel geschlossen; danach liefert
    ///   [`ExecEvents::exit_status`] den endgültigen Status.
    /// * `Err(..)`: Die Verbindung ist abgebrochen.
    ///
    /// Der Aufruf ist abbruchsicher: Wird das Future fallen gelassen (z.B. von
    /// `tokio::time::timeout`), geht nichts verloren.
    pub async fn next(&mut self) -> Result<Option<ExecEvent>> {
        loop {
            match self.reader.next_event().await {
                Some(Event::Data(d)) => return Ok(Some(ExecEvent::Stdout(d))),
                Some(Event::Stderr(d)) => return Ok(Some(ExecEvent::Stderr(d))),
                Some(Event::Eof) => continue,
                Some(Event::Close) => {
                    self.done = true;
                    return Ok(None);
                }
                None if self.done => return Ok(None),
                None => return Err(self.reader.lost_error()),
            }
        }
    }

    /// Wie der Befehl endete; erst gültig, nachdem [`ExecEvents::next`] `Ok(None)` lieferte
    /// (vorher `ExitStatus::Unknown`).
    pub fn exit_status(&self) -> ExitStatus {
        self.reader.core.exit_status()
    }
}

impl AsyncWrite for ExecStdin {
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

impl std::fmt::Debug for ExecStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecStream").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ExecStdin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecStdin").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ExecEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecEvents")
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}
