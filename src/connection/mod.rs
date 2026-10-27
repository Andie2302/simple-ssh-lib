//! Connection-Protokoll (RFC 4254). Bisher: `exec` auf einem Session-Channel.
//!
//! Channels werden nacheinander benutzt (`&mut self`); parallele Channels auf
//! einer Verbindung gibt es nicht.

mod exec;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};

use crate::auth::authenticate;
use crate::error::Result;
use crate::keys::PrivateKey;
use crate::transport::{HostKeyCheck, Transport};

pub use exec::{ExecOutput, ExitStatus};

/// Standardgrenze für die gesammelte Ausgabe eines Befehls (stdout + stderr).
pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024 * 1024;

/// Verbindungsparameter. Host-Key-Prüfung und Key sind Pflicht.
pub struct Config {
    pub user: String,
    pub key: PrivateKey,
    pub host_key: HostKeyCheck,
    /// Obergrenze für stdout + stderr eines `exec`; danach `Error::OutputTooLarge`.
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

/// Angemeldete SSH-Sitzung.
pub struct Session<S> {
    transport: Transport<S>,
    next_channel: u32,
    max_output: usize,
}

impl Session<TcpStream> {
    /// Verbindet per TCP, führt Handshake und Anmeldung aus.
    pub async fn connect(addr: impl ToSocketAddrs, config: Config) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Self::from_stream(stream, config).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    /// Wie [`Session::connect`], aber über einen bereits offenen Stream.
    pub async fn from_stream(stream: S, config: Config) -> Result<Self> {
        let mut transport = Transport::connect(stream, &config.host_key).await?;
        authenticate(&mut transport, &config.user, &config.key).await?;
        Ok(Self {
            transport,
            next_channel: 0,
            max_output: config.max_output,
        })
    }

    pub fn transport(&self) -> &Transport<S> {
        &self.transport
    }
}
