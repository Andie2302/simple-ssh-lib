//! `exec`: einen Befehl ausführen und stdout, stderr und Exit-Status sammeln.
//!
//! Flow-Control: Wir kündigen ein Empfangsfenster von [`WINDOW`] Bytes an und
//! erweitern es per `WINDOW_ADJUST`, sobald weniger als die Hälfte übrig ist.
//! Eingabe (stdin) wird bei `exec` nicht gesendet: direkt nach dem Start folgt EOF.

use tokio::io::{AsyncRead, AsyncWrite};

use super::Session;
use crate::error::{Error, Result};
use crate::wire::{Reader, Writer};

const MSG_GLOBAL_REQUEST: u8 = 80;
const MSG_REQUEST_FAILURE: u8 = 82;
const MSG_CHANNEL_OPEN: u8 = 90;
const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
const MSG_CHANNEL_DATA: u8 = 94;
const MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
const MSG_CHANNEL_EOF: u8 = 96;
const MSG_CHANNEL_CLOSE: u8 = 97;
const MSG_CHANNEL_REQUEST: u8 = 98;
const MSG_CHANNEL_SUCCESS: u8 = 99;
const MSG_CHANNEL_FAILURE: u8 = 100;

const EXTENDED_DATA_STDERR: u32 = 1;
/// Empfangsfenster (OpenSSH-Standard).
const WINDOW: u32 = 2 * 1024 * 1024;
/// Größte Datenmenge pro Paket, die wir annehmen.
const MAX_PACKET: u32 = 32 * 1024;

/// Wie ein Befehl beendet wurde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitStatus {
    Code(u32),
    /// Durch ein Signal beendet (Name ohne `SIG`, z.B. `KILL`).
    Signal(String),
    /// Der Server hat keinen Status gemeldet.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit: ExitStatus,
}

impl ExecOutput {
    pub fn success(&self) -> bool {
        self.exit == ExitStatus::Code(0)
    }
}

fn violation<T>(what: &'static str) -> Result<T> {
    Err(Error::ProtocolViolation(what))
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    /// Führt `command` auf dem Server aus und wartet auf das Ende.
    pub async fn exec(&mut self, command: &str) -> Result<ExecOutput> {
        let local = self.next_channel;
        self.next_channel += 1;

        // Channel öffnen.
        let mut w = Writer::new();
        w.put_u8(MSG_CHANNEL_OPEN)
            .put_string(b"session")
            .put_u32(local)
            .put_u32(WINDOW)
            .put_u32(MAX_PACKET);
        self.transport.send(w.as_slice()).await?;

        let msg = self.next_message().await?;
        let mut r = Reader::new(&msg[1..]);
        let remote = match msg[0] {
            MSG_CHANNEL_OPEN_CONFIRMATION => {
                if r.get_u32()? != local {
                    return violation("open confirmation for unknown channel");
                }
                let remote = r.get_u32()?;
                r.get_u32()?; // Fenster des Servers: wir senden nichts
                r.get_u32()?; // max. Paketgröße des Servers
                r.finish()?;
                remote
            }
            MSG_CHANNEL_OPEN_FAILURE => {
                if r.get_u32()? != local {
                    return violation("open failure for unknown channel");
                }
                let reason = r.get_u32()?;
                let message = String::from_utf8_lossy(r.get_string()?).into_owned();
                return Err(Error::ChannelOpenFailed { reason, message });
            }
            _ => return violation("unexpected reply to channel open"),
        };

        // Befehl starten.
        let mut w = Writer::new();
        w.put_u8(MSG_CHANNEL_REQUEST)
            .put_u32(remote)
            .put_string(b"exec")
            .put_bool(true)
            .put_string(command.as_bytes());
        self.transport.send(w.as_slice()).await?;
        loop {
            let msg = self.next_message().await?;
            let mut r = Reader::new(&msg[1..]);
            match msg[0] {
                MSG_CHANNEL_WINDOW_ADJUST => {
                    if r.get_u32()? != local {
                        return violation("window adjust for unknown channel");
                    }
                }
                MSG_CHANNEL_SUCCESS => break,
                MSG_CHANNEL_FAILURE => {
                    self.send_channel(MSG_CHANNEL_CLOSE, remote).await?;
                    self.wait_for_close(local).await?;
                    return Err(Error::CommandRejected);
                }
                _ => return violation("unexpected reply to exec request"),
            }
        }
        // Kein stdin: dem Befehl sofort EOF melden.
        self.send_channel(MSG_CHANNEL_EOF, remote).await?;

        self.collect_output(local, remote).await
    }

    async fn collect_output(&mut self, local: u32, remote: u32) -> Result<ExecOutput> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit = ExitStatus::Unknown;
        let mut window = WINDOW;
        let mut sent_close = false;
        let mut overflow = false;

        loop {
            let msg = self.next_message().await?;
            let kind = msg[0];
            let mut r = Reader::new(&msg[1..]);
            let recipient = r.get_u32()?;
            if recipient != local {
                return violation("message for unknown channel");
            }
            match kind {
                MSG_CHANNEL_DATA | MSG_CHANNEL_EXTENDED_DATA => {
                    let stream = if kind == MSG_CHANNEL_EXTENDED_DATA {
                        Some(r.get_u32()?)
                    } else {
                        None
                    };
                    let data = r.get_string()?;
                    r.finish()?;
                    if data.len() > MAX_PACKET as usize {
                        return violation("data packet larger than announced maximum");
                    }
                    window = match window.checked_sub(data.len() as u32) {
                        Some(w) => w,
                        None => return violation("peer exceeded receive window"),
                    };
                    if !overflow {
                        match stream {
                            None => stdout.extend_from_slice(data),
                            Some(EXTENDED_DATA_STDERR) => stderr.extend_from_slice(data),
                            Some(_) => {}
                        }
                        if stdout.len() + stderr.len() > self.max_output {
                            // Ausgabe verwerfen, Channel schließen, auf Gegenstelle warten.
                            overflow = true;
                            stdout = Vec::new();
                            stderr = Vec::new();
                            self.send_channel(MSG_CHANNEL_CLOSE, remote).await?;
                            sent_close = true;
                        }
                    }
                    if !sent_close && window < WINDOW / 2 {
                        let mut w = Writer::new();
                        w.put_u8(MSG_CHANNEL_WINDOW_ADJUST)
                            .put_u32(remote)
                            .put_u32(WINDOW - window);
                        self.transport.send(w.as_slice()).await?;
                        window = WINDOW;
                    }
                }
                MSG_CHANNEL_EOF | MSG_CHANNEL_WINDOW_ADJUST => {}
                MSG_CHANNEL_REQUEST => {
                    let name = r.get_string()?;
                    let want_reply = r.get_bool()?;
                    match name {
                        b"exit-status" => exit = ExitStatus::Code(r.get_u32()?),
                        b"exit-signal" => {
                            exit = ExitStatus::Signal(
                                String::from_utf8_lossy(r.get_string()?).into_owned(),
                            )
                        }
                        _ => {}
                    }
                    if want_reply && !sent_close {
                        self.send_channel(MSG_CHANNEL_FAILURE, remote).await?;
                    }
                }
                MSG_CHANNEL_CLOSE => {
                    if !sent_close {
                        self.send_channel(MSG_CHANNEL_CLOSE, remote).await?;
                    }
                    break;
                }
                _ => return violation("unexpected message on channel"),
            }
        }

        if overflow {
            return Err(Error::OutputTooLarge);
        }
        Ok(ExecOutput {
            stdout,
            stderr,
            exit,
        })
    }

    /// Wartet auf CLOSE des Servers (nach Fehlern), verwirft alles andere.
    async fn wait_for_close(&mut self, local: u32) -> Result<()> {
        loop {
            let msg = self.next_message().await?;
            let mut r = Reader::new(&msg[1..]);
            if r.get_u32()? != local {
                return violation("message for unknown channel");
            }
            if msg[0] == MSG_CHANNEL_CLOSE {
                return Ok(());
            }
        }
    }

    /// Sendet eine Channel-Nachricht, die nur aus Typ und Empfänger besteht.
    async fn send_channel(&mut self, kind: u8, remote: u32) -> Result<()> {
        let mut w = Writer::new();
        w.put_u8(kind).put_u32(remote);
        self.transport.send(w.as_slice()).await
    }

    /// Nächste Nachricht; globale Requests des Servers werden hier beantwortet.
    async fn next_message(&mut self) -> Result<Vec<u8>> {
        loop {
            let msg = self.transport.recv().await?;
            if msg[0] != MSG_GLOBAL_REQUEST {
                return Ok(msg);
            }
            let mut r = Reader::new(&msg[1..]);
            r.get_string()?; // Name, z.B. hostkeys-00@openssh.com
            if r.get_bool()? {
                self.transport.send(&[MSG_REQUEST_FAILURE]).await?;
            }
        }
    }
}
