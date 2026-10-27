//! `exec`: einen Befehl ausführen und stdout, stderr und Exit-Status sammeln.

use tokio::io::AsyncWriteExt;

use super::Session;
use super::channel::{ChannelReader, ExitStatus, open_session};
use super::mux::Event;
use crate::error::{Error, Result};
use crate::wire::check_field;

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

impl Session {
    /// Führt `command` aus (ohne Eingabe: der Befehl sieht sofort EOF auf stdin).
    pub async fn exec(&self, command: &str) -> Result<ExecOutput> {
        self.exec_with_input(command, &[]).await
    }

    /// Führt `command` aus und schickt `input` an dessen stdin.
    ///
    /// Eingabe und Ausgabe laufen gleichzeitig; es gibt also kein Blockieren, wenn
    /// der Befehl schon ausgibt, bevor er alles gelesen hat. Beendet sich der
    /// Befehl, ohne die ganze Eingabe zu lesen, ist das kein Fehler.
    pub async fn exec_with_input(&self, command: &str, input: &[u8]) -> Result<ExecOutput> {
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

        let super::channel::Channel { reader, mut writer } = channel;
        let feed = async move {
            let _ = writer.write_all(input).await;
            let _ = writer.shutdown().await;
            writer // Channel bis zum Ende offen halten
        };
        let (_writer, output) = tokio::join!(feed, collect(reader, self.max_output));
        output
    }
}

async fn collect(mut reader: ChannelReader, max_output: usize) -> Result<ExecOutput> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut overflow = false;

    loop {
        let chunk = match reader.next_event().await {
            Some(Event::Data(d)) => (&mut stdout, d),
            Some(Event::Stderr(d)) => (&mut stderr, d),
            Some(Event::Eof) => continue,
            Some(Event::Close) => break,
            None => return Err(reader.lost_error()),
        };
        if overflow {
            continue;
        }
        let (target, data) = chunk;
        target.extend_from_slice(&data);
        if stdout.len() + stderr.len() > max_output {
            // Ausgabe verwerfen, Channel schließen und auf CLOSE der Gegenstelle warten.
            overflow = true;
            stdout = Vec::new();
            stderr = Vec::new();
            reader.core.close();
        }
    }

    if overflow {
        return Err(Error::OutputTooLarge);
    }
    Ok(ExecOutput {
        stdout,
        stderr,
        exit: reader.core.exit_status(),
    })
}
