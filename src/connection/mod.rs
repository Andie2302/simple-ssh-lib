//! Connection-Protokoll (RFC 4254): Sessions mit `exec` und interaktiver Shell.
//!
//! Eine [`Session`] betreibt im Hintergrund zwei Tokio-Tasks (lesen/schreiben).
//! Alle Methoden nehmen `&self`; mehrere Befehle und Shells können gleichzeitig
//! auf einer Verbindung laufen.

mod channel;
mod exec;
mod mux;
mod shell;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};

use crate::auth::authenticate;
use crate::error::Result;
use crate::keys::PrivateKey;
use crate::transport::{HostKeyCheck, Transport};

pub use channel::ExitStatus;
pub(crate) use channel::open_session;
pub use exec::ExecOutput;
pub use shell::{Pty, Shell};

/// Standardgrenze für die gesammelte Ausgabe eines Befehls (stdout + stderr).
pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024 * 1024;

/// Verbindungsparameter. Host-Key-Prüfung und Key sind Pflicht.
pub struct Config {
    pub user: String,
    pub key: PrivateKey,
    pub host_key: HostKeyCheck,
    /// Obergrenze für gesammelte Daten (stdout + stderr eines `exec`, `Sftp::read`);
    /// danach `Error::OutputTooLarge`.
    pub max_output: usize,
}

impl Config {
    pub fn new(user: impl Into<String>, key: PrivateKey, host_key: HostKeyCheck) -> Self {
        Self {
            user: user.into(),
            key,
            host_key,
            max_output: DEFAULT_MAX_OUTPUT,
        }
    }

    pub fn max_output(mut self, bytes: usize) -> Self {
        self.max_output = bytes;
        self
    }
}

/// Angemeldete SSH-Sitzung. Wird die letzte Kopie (Session, Shell) fallen
/// gelassen, trennt die Verbindung mit `SSH_MSG_DISCONNECT`.
pub struct Session {
    pub(crate) handle: mux::Handle,
    pub(crate) max_output: usize,
    server_banner: String,
    host_key_fingerprint: String,
}

impl Session {
    /// Verbindet per TCP, führt Handshake und Anmeldung aus.
    pub async fn connect(addr: impl ToSocketAddrs, config: Config) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Self::from_stream(stream, config).await
    }

    /// Wie [`Session::connect`], aber über einen bereits offenen Stream.
    /// Muss innerhalb einer Tokio-Runtime aufgerufen werden.
    pub async fn from_stream<S>(stream: S, config: Config) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut transport = Transport::connect(stream, &config.host_key).await?;
        authenticate(&mut transport, &config.user, &config.key).await?;
        let server_banner = transport.server_banner().to_owned();
        let host_key_fingerprint = transport.host_key_fingerprint().to_owned();
        let (recv, send) = transport.into_split();
        Ok(Self {
            handle: mux::spawn(recv, send),
            max_output: config.max_output,
            server_banner,
            host_key_fingerprint,
        })
    }

    pub fn server_banner(&self) -> &str {
        &self.server_banner
    }

    pub fn host_key_fingerprint(&self) -> &str {
        &self.host_key_fingerprint
    }
}
