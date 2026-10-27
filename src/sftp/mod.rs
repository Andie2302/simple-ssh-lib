//! SFTP-Client (Protokollversion 3) über das `sftp`-Subsystem einer Session.
//!
//! Ist das Subsystem auf dem Server nicht verfügbar, gibt es
//! [`Error::SftpUnavailable`]; SCP oder andere Ersatzwege gibt es nicht.
//!
//! Pfade sind `&str`. Dateinamen, die der Server als Nicht-UTF-8 liefert, werden
//! beim Auflisten mit Ersatzzeichen dargestellt.

mod client;
mod file;
mod proto;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::connection::{Session, open_session};
use crate::error::{Error, Result};
use crate::wire::{Writer, check_field};
use client::Client;
use proto::*;

pub use file::{File, OpenOptions};
pub use proto::{DirEntry, Metadata, SftpStatus};

/// Nur für Robustheitstests (siehe `fuzz_api`).
pub(crate) fn parse_response_for_fuzzing(packet: &[u8]) -> bool {
    proto::parse_response(packet).is_ok()
}

/// Schutz vor Servern, die endlos Verzeichniseinträge liefern.
const MAX_DIR_ENTRIES: usize = 1_000_000;

pub(crate) fn unexpected<T>() -> Result<T> {
    Err(Error::ProtocolViolation("unexpected sftp response type"))
}

pub(crate) fn status_error(status: SftpStatus, message: String) -> Error {
    Error::Sftp { status, message }
}

pub(crate) fn put_path(w: &mut Writer, path: &str) {
    w.put_string(path.as_bytes());
}

pub(crate) fn expect_ok(response: Response) -> Result<()> {
    match response {
        Response::Status {
            status: SftpStatus::Ok,
            ..
        } => Ok(()),
        Response::Status { status, message } => Err(status_error(status, message)),
        _ => unexpected(),
    }
}

pub(crate) fn expect_handle(response: Response) -> Result<Vec<u8>> {
    match response {
        Response::Handle(h) => Ok(h),
        Response::Status { status, message } => Err(status_error(status, message)),
        _ => unexpected(),
    }
}

pub(crate) fn expect_attrs(response: Response) -> Result<Metadata> {
    match response {
        Response::Attrs(m) => Ok(m),
        Response::Status { status, message } => Err(status_error(status, message)),
        _ => unexpected(),
    }
}

/// SFTP-Verbindung. Günstig zu klonen; alle Methoden nehmen `&self` und dürfen
/// gleichzeitig aus mehreren Tasks aufgerufen werden.
#[derive(Clone)]
pub struct Sftp {
    pub(crate) client: Client,
    max_read: usize,
}

impl std::fmt::Debug for Sftp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sftp")
            .field("max_read", &self.max_read)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Startet das `sftp`-Subsystem. Die Obergrenze für [`Sftp::read`] ist
    /// `Config::max_output`.
    pub async fn sftp(&self) -> Result<Sftp> {
        let channel = open_session(&self.handle).await?;
        let accepted = channel
            .core()
            .request("subsystem", |w| {
                w.put_string(b"sftp");
            })
            .await;
        match accepted {
            Ok(true) => {}
            Ok(false) => {
                return Err(Error::SftpUnavailable(
                    "the server refused the `sftp` subsystem".into(),
                ));
            }
            // Schließt der Server den Channel statt zu antworten, ist die Verbindung
            // selbst noch in Ordnung.
            Err(Error::ConnectionLost(_)) if !self.handle.is_lost() => {
                return Err(Error::SftpUnavailable(
                    "the server closed the channel when the `sftp` subsystem was requested".into(),
                ));
            }
            Err(e) => return Err(e),
        }
        Ok(Sftp::from_stream(channel).await?.max_read(self.max_output))
    }
}

impl Sftp {
    /// SFTP über einen beliebigen, bereits verbundenen Byte-Stream (z.B. für Tests).
    pub async fn from_stream<S>(stream: S) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Ok(Self {
            client: Client::connect(stream).await?,
            max_read: crate::connection::DEFAULT_MAX_OUTPUT,
        })
    }

    /// Obergrenze für [`Sftp::read`] in Bytes.
    pub fn max_read(mut self, bytes: usize) -> Self {
        self.max_read = bytes;
        self
    }

    /// Öffnet eine Datei zum Lesen.
    pub async fn open(&self, path: &str) -> Result<File> {
        OpenOptions::new().read(true).open(self, path).await
    }

    /// Legt eine Datei an oder leert sie, zum Schreiben.
    pub async fn create(&self, path: &str) -> Result<File> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(self, path)
            .await
    }

    /// Liest eine ganze Datei. Mehr als die konfigurierte Obergrenze ergibt
    /// [`Error::OutputTooLarge`].
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        check_field(path, "path")?;
        let file = self.open(path).await?;
        let size = file.metadata().await.ok().and_then(|m| m.size);
        let data = file.read_range(0, self.max_read, size).await;
        // Ein Fehler beim Schließen einer nur gelesenen Datei ändert das Ergebnis nicht.
        let _ = file.close().await;
        data
    }

    /// Schreibt `data` in eine neue oder vorhandene Datei (vorhandener Inhalt wird ersetzt).
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        check_field(path, "path")?;
        let file = self.create(path).await?;
        let written = file.write_all_at(0, data).await;
        let closed = file.close().await;
        written.and(closed)
    }

    /// Listet ein Verzeichnis ohne `.` und `..`, in der Reihenfolge des Servers.
    pub async fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        check_field(path, "path")?;
        let handle = expect_handle(
            self.client
                .call(FXP_OPENDIR, |w| {
                    put_path(w, path);
                })
                .await?,
        )?;
        let mut entries = Vec::new();
        let listing = self.fill_dir(&handle, &mut entries).await;
        let closed = self.close_handle(&handle).await;
        listing.and(closed)?;
        Ok(entries)
    }

    async fn fill_dir(&self, handle: &[u8], entries: &mut Vec<DirEntry>) -> Result<()> {
        loop {
            let response = self
                .client
                .call(FXP_READDIR, |w| {
                    w.put_string(handle);
                })
                .await?;
            match response {
                Response::Name(batch) => {
                    entries.extend(
                        batch
                            .into_iter()
                            .filter(|e| e.name != "." && e.name != ".."),
                    );
                    if entries.len() > MAX_DIR_ENTRIES {
                        return Err(Error::OutputTooLarge);
                    }
                }
                Response::Status {
                    status: SftpStatus::Eof,
                    ..
                } => return Ok(()),
                Response::Status { status, message } => return Err(status_error(status, message)),
                _ => return unexpected(),
            }
        }
    }

    async fn close_handle(&self, handle: &[u8]) -> Result<()> {
        expect_ok(
            self.client
                .call(FXP_CLOSE, |w| {
                    w.put_string(handle);
                })
                .await?,
        )
    }

    /// Attribute einer Datei; folgt Symlinks.
    pub async fn metadata(&self, path: &str) -> Result<Metadata> {
        check_field(path, "path")?;
        expect_attrs(
            self.client
                .call(FXP_STAT, |w| {
                    put_path(w, path);
                })
                .await?,
        )
    }

    /// Attribute einer Datei; folgt Symlinks nicht.
    pub async fn symlink_metadata(&self, path: &str) -> Result<Metadata> {
        check_field(path, "path")?;
        expect_attrs(
            self.client
                .call(FXP_LSTAT, |w| {
                    put_path(w, path);
                })
                .await?,
        )
    }

    /// Legt ein Verzeichnis an (`mode`: Unix-Modus, sonst Standard des Servers).
    pub async fn create_dir(&self, path: &str, mode: Option<u32>) -> Result<()> {
        check_field(path, "path")?;
        let attrs = Metadata {
            permissions: mode,
            ..Metadata::default()
        };
        expect_ok(
            self.client
                .call(FXP_MKDIR, |w| {
                    put_path(w, path);
                    attrs.encode(w);
                })
                .await?,
        )
    }

    /// Löscht ein leeres Verzeichnis.
    pub async fn remove_dir(&self, path: &str) -> Result<()> {
        check_field(path, "path")?;
        expect_ok(
            self.client
                .call(FXP_RMDIR, |w| {
                    put_path(w, path);
                })
                .await?,
        )
    }

    /// Löscht eine Datei.
    pub async fn remove_file(&self, path: &str) -> Result<()> {
        check_field(path, "path")?;
        expect_ok(
            self.client
                .call(FXP_REMOVE, |w| {
                    put_path(w, path);
                })
                .await?,
        )
    }

    /// Benennt um. OpenSSH überschreibt ein vorhandenes Ziel nicht (Fehler `Failure`).
    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        check_field(from, "path")?;
        check_field(to, "path")?;
        expect_ok(
            self.client
                .call(FXP_RENAME, |w| {
                    put_path(w, from);
                    put_path(w, to);
                })
                .await?,
        )
    }

    /// Setzt den Unix-Modus einer Datei.
    pub async fn set_permissions(&self, path: &str, mode: u32) -> Result<()> {
        check_field(path, "path")?;
        let attrs = Metadata {
            permissions: Some(mode),
            ..Metadata::default()
        };
        expect_ok(
            self.client
                .call(FXP_SETSTAT, |w| {
                    put_path(w, path);
                    attrs.encode(w);
                })
                .await?,
        )
    }

    /// Absoluter, aufgelöster Pfad (`realpath`).
    pub async fn canonicalize(&self, path: &str) -> Result<String> {
        check_field(path, "path")?;
        match self
            .client
            .call(FXP_REALPATH, |w| {
                put_path(w, path);
            })
            .await?
        {
            Response::Name(mut entries) if entries.len() == 1 => Ok(entries.remove(0).name),
            Response::Status { status, message } => Err(status_error(status, message)),
            _ => unexpected(),
        }
    }
}
