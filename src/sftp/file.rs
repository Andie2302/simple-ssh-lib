//! Offene Dateien auf dem Server und gepipelinetes Lesen/Schreiben.

use std::collections::VecDeque;
use std::io::{self, SeekFrom};

use super::client::{Client, Pending};
use super::proto::{
    FXP_CLOSE, FXP_FSETSTAT, FXP_FSTAT, FXP_OPEN, FXP_READ, FXP_WRITE, Metadata, PFLAG_APPEND,
    PFLAG_CREAT, PFLAG_EXCL, PFLAG_READ, PFLAG_TRUNC, PFLAG_WRITE, Response, SftpStatus,
};
use super::{Sftp, expect_attrs, expect_handle, expect_ok, put_path, status_error, unexpected};
use crate::error::{Error, Result};

/// Datenmenge pro READ/WRITE-Anfrage.
const CHUNK: usize = 32 * 1024;
/// Anzahl gleichzeitig offener READ/WRITE-Anfragen.
const DEPTH: usize = 16;
/// Mehr als das reservieren wir nie im Voraus, egal was der Server als Größe meldet.
const MAX_PREALLOC: usize = 16 * 1024 * 1024;

fn invalid_input(what: &'static str) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidInput, what))
}

/// Öffnungsmodus, angelehnt an `std::fs::OpenOptions`.
#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    create: bool,
    truncate: bool,
    create_new: bool,
    mode: Option<u32>,
}

impl OpenOptions {
    /// Alle Optionen aus; mindestens eine von `read`, `write`, `append` ist nötig.
    pub fn new() -> Self {
        Self::default()
    }

    /// Zum Lesen öffnen.
    pub fn read(&mut self, on: bool) -> &mut Self {
        self.read = on;
        self
    }

    /// Zum Schreiben öffnen.
    pub fn write(&mut self, on: bool) -> &mut Self {
        self.write = on;
        self
    }

    /// Schreibt immer ans Dateiende (der Server ignoriert dann den Offset).
    pub fn append(&mut self, on: bool) -> &mut Self {
        self.append = on;
        self
    }

    /// Datei anlegen, falls sie fehlt (setzt Schreiben voraus).
    pub fn create(&mut self, on: bool) -> &mut Self {
        self.create = on;
        self
    }

    /// Vorhandenen Inhalt beim Öffnen löschen (setzt Schreiben voraus).
    pub fn truncate(&mut self, on: bool) -> &mut Self {
        self.truncate = on;
        self
    }

    /// Legt die Datei an und scheitert, wenn sie schon existiert.
    pub fn create_new(&mut self, on: bool) -> &mut Self {
        self.create_new = on;
        self
    }

    /// Unix-Modus für neu angelegte Dateien (sonst Standard des Servers).
    pub fn mode(&mut self, mode: u32) -> &mut Self {
        self.mode = Some(mode);
        self
    }

    fn pflags(&self) -> Result<u32> {
        if !(self.read || self.write || self.append) {
            return Err(invalid_input("open options need read, write or append"));
        }
        let writing = self.write || self.append;
        if !writing && (self.create || self.truncate || self.create_new) {
            return Err(invalid_input("create/truncate need write or append"));
        }
        if self.append && self.truncate {
            return Err(invalid_input("append and truncate cannot be combined"));
        }
        let mut flags = 0;
        if self.read {
            flags |= PFLAG_READ;
        }
        if writing {
            flags |= PFLAG_WRITE;
        }
        if self.append {
            flags |= PFLAG_APPEND;
        }
        if self.create_new {
            flags |= PFLAG_CREAT | PFLAG_EXCL;
        } else if self.create {
            flags |= PFLAG_CREAT;
        }
        if self.truncate {
            flags |= PFLAG_TRUNC;
        }
        Ok(flags)
    }

    /// Öffnet `path` mit diesen Optionen.
    pub async fn open(&self, sftp: &Sftp, path: &str) -> Result<File> {
        crate::wire::check_field(path, "path")?;
        let flags = self.pflags()?;
        let attrs = Metadata {
            permissions: self.mode,
            ..Metadata::default()
        };
        let response = sftp
            .client
            .call(FXP_OPEN, |w| {
                put_path(w, path);
                w.put_u32(flags);
                attrs.encode(w);
            })
            .await?;
        Ok(File {
            client: sftp.client.clone(),
            handle: expect_handle(response)?,
            pos: 0,
            closed: false,
        })
    }
}

/// Eine auf dem Server geöffnete Datei. Jede Operation ist ein Netzwerk-Roundtrip.
///
/// Mit [`File::close`] wird das Handle geprüft geschlossen; beim Fallenlassen
/// wird es nur nach bestem Wissen und ohne Fehlermeldung geschlossen.
pub struct File {
    client: Client,
    handle: Vec<u8>,
    pos: u64,
    closed: bool,
}

impl File {
    /// Liest höchstens `buf.len()` (und höchstens 32 KiB) Bytes ab `offset`.
    /// `0` bedeutet Dateiende.
    pub async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(CHUNK);
        let response = self
            .client
            .call(FXP_READ, |w| {
                w.put_string(&self.handle)
                    .put_u64(offset)
                    .put_u32(len as u32);
            })
            .await?;
        match response {
            Response::Data(d) if !d.is_empty() && d.len() <= len => {
                buf[..d.len()].copy_from_slice(&d);
                Ok(d.len())
            }
            Response::Data(_) => Err(Error::ProtocolViolation(
                "sftp read returned invalid data length",
            )),
            Response::Status {
                status: SftpStatus::Eof,
                ..
            } => Ok(0),
            Response::Status { status, message } => Err(status_error(status, message)),
            _ => unexpected(),
        }
    }

    /// Liest ab der aktuellen Position (siehe [`File::read_at`]).
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.read_at(self.pos, buf).await?;
        self.pos += n as u64;
        Ok(n)
    }

    /// Liest bis zum Dateiende, höchstens `limit` Bytes; mehr ergibt `OutputTooLarge`.
    pub async fn read_to_end(&mut self, limit: usize) -> Result<Vec<u8>> {
        let data = self.read_range(self.pos, limit, None).await?;
        self.pos += data.len() as u64;
        Ok(data)
    }

    /// Gepipelinetes Lesen ab `start`. `size_hint` (z.B. aus `fstat`) dient nur der
    /// Vorab-Reservierung und dazu, den letzten, ohnehin kurzen Block ohne
    /// zusätzlichen Roundtrip als Dateiende zu erkennen.
    pub(crate) async fn read_range(
        &self,
        start: u64,
        limit: usize,
        size_hint: Option<u64>,
    ) -> Result<Vec<u8>> {
        struct Request {
            offset: u64,
            len: usize,
            pending: Pending,
        }

        let prealloc =
            size_hint.map_or(0, |s| s.min(limit as u64).min(MAX_PREALLOC as u64) as usize);
        let mut out = Vec::with_capacity(prealloc);
        let mut queue: VecDeque<Request> = VecDeque::new();
        let mut next = start;

        loop {
            // Eine Anfrage über `limit` hinaus bleibt erlaubt, damit Überlauf auffällt.
            while queue.len() < DEPTH && next - start <= limit as u64 {
                let pending = self.client.start(FXP_READ, |w| {
                    w.put_string(&self.handle)
                        .put_u64(next)
                        .put_u32(CHUNK as u32);
                })?;
                queue.push_back(Request {
                    offset: next,
                    len: CHUNK,
                    pending,
                });
                next += CHUNK as u64;
            }
            let Some(request) = queue.pop_front() else {
                break;
            };
            match request.pending.wait().await? {
                Response::Data(d) => {
                    if d.is_empty() || d.len() > request.len {
                        return Err(Error::ProtocolViolation(
                            "sftp read returned invalid data length",
                        ));
                    }
                    if out.len() + d.len() > limit {
                        return Err(Error::OutputTooLarge);
                    }
                    out.extend_from_slice(&d);
                    if d.len() < request.len {
                        // Kurze Antwort: Das ist entweder das Dateiende oder ein Server, der
                        // weniger liefert als angefragt. Später angefragte Blöcke wären dann
                        // lückenhaft, also verwerfen und ab dem echten Stand neu starten.
                        let reached = request.offset + d.len() as u64;
                        if size_hint == Some(reached) {
                            break;
                        }
                        queue.clear();
                        next = reached;
                    }
                }
                Response::Status {
                    status: SftpStatus::Eof,
                    ..
                } => break,
                Response::Status { status, message } => return Err(status_error(status, message)),
                _ => return unexpected(),
            }
        }
        Ok(out)
    }

    /// Schreibt höchstens 32 KiB ab der aktuellen Position und liefert die Anzahl.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let n = buf.len().min(CHUNK);
        self.write_all_at(self.pos, &buf[..n]).await?;
        self.pos += n as u64;
        Ok(n)
    }

    /// Schreibt alles ab der aktuellen Position.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.write_all_at(self.pos, data).await?;
        self.pos += data.len() as u64;
        Ok(())
    }

    /// Schreibt alles ab `offset`, mit mehreren Anfragen gleichzeitig.
    pub async fn write_all_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        let mut sent = 0;
        let mut queue: VecDeque<Pending> = VecDeque::new();
        loop {
            while sent < data.len() && queue.len() < DEPTH {
                let end = (sent + CHUNK).min(data.len());
                let at = offset + sent as u64;
                let chunk = &data[sent..end];
                queue.push_back(self.client.start(FXP_WRITE, |w| {
                    w.put_string(&self.handle).put_u64(at).put_string(chunk);
                })?);
                sent = end;
            }
            match queue.pop_front() {
                // Bei einem Fehler werden die übrigen Antworten verworfen.
                Some(pending) => expect_ok(pending.wait().await?)?,
                None => return Ok(()),
            }
        }
    }

    /// Setzt die Position für `read`/`write`. `SeekFrom::End` fragt die Größe ab.
    pub async fn seek(&mut self, to: SeekFrom) -> Result<u64> {
        let target = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
            SeekFrom::End(d) => {
                let size = self
                    .metadata()
                    .await?
                    .size
                    .ok_or(Error::Malformed("server did not report a file size"))?;
                size.checked_add_signed(d)
            }
        };
        self.pos = target.ok_or_else(|| invalid_input("seek before start of file"))?;
        Ok(self.pos)
    }

    /// Aktuelle Position für `read`/`write`.
    pub fn position(&self) -> u64 {
        self.pos
    }

    /// Attribute der offenen Datei (`fstat`).
    pub async fn metadata(&self) -> Result<Metadata> {
        let response = self
            .client
            .call(FXP_FSTAT, |w| {
                w.put_string(&self.handle);
            })
            .await?;
        expect_attrs(response)
    }

    /// Kürzt oder verlängert die Datei auf `size` Bytes.
    pub async fn set_len(&self, size: u64) -> Result<()> {
        let attrs = Metadata {
            size: Some(size),
            ..Metadata::default()
        };
        let response = self
            .client
            .call(FXP_FSETSTAT, |w| {
                w.put_string(&self.handle);
                attrs.encode(w);
            })
            .await?;
        expect_ok(response)
    }

    /// Schließt die Datei und meldet Fehler des Servers (z.B. beim Zurückschreiben).
    pub async fn close(mut self) -> Result<()> {
        self.closed = true;
        let response = self
            .client
            .call(FXP_CLOSE, |w| {
                w.put_string(&self.handle);
            })
            .await?;
        expect_ok(response)
    }
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("File")
            .field("position", &self.pos)
            .finish_non_exhaustive()
    }
}

impl Drop for File {
    fn drop(&mut self) {
        if !self.closed {
            // Fire and forget: `start` wartet nicht, die Antwort wird verworfen.
            let _ = self.client.start(FXP_CLOSE, |w| {
                w.put_string(&self.handle);
            });
        }
    }
}
