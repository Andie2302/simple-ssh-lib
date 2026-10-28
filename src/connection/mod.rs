//! Connection-Protokoll (RFC 4254): Sessions mit `exec` und interaktiver Shell.
//!
//! Eine [`Session`] betreibt im Hintergrund zwei Tokio-Tasks (lesen/schreiben).
//! Alle Methoden nehmen `&self`; mehrere Befehle und Shells können gleichzeitig
//! auf einer Verbindung laufen.

mod channel;
mod exec;
mod exec_stream;
mod mux;
mod shell;

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};

use crate::auth::authenticate;
use crate::error::{Error, Result};
use crate::keys::PrivateKey;
use crate::transport::{HostKeyCheck, Transport};

pub use channel::ExitStatus;
pub(crate) use channel::open_session;
pub use exec::ExecOutput;
pub use exec_stream::{ExecEvent, ExecEvents, ExecStdin, ExecStream};
pub(crate) use mux::fuzz_dispatch;
pub use shell::{Pty, Shell, ShellControl, ShellReader, ShellWriter};

/// Standardgrenze für die gesammelte Ausgabe eines Befehls (stdout + stderr).
pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024 * 1024;

/// Datenmenge, nach der wir die Schlüssel wechseln.
pub const DEFAULT_REKEY_BYTES: u64 = 1024 * 1024 * 1024;
/// Zeit, nach der wir die Schlüssel wechseln.
pub const DEFAULT_REKEY_INTERVAL: Duration = Duration::from_secs(3600);

/// Standardfrist für Verbindungsaufbau, Handshake und Anmeldung.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Verbindungsparameter. Host-Key-Prüfung und Key sind Pflicht.
#[non_exhaustive]
pub struct Config {
    /// Benutzername auf dem Server.
    pub user: String,
    /// Privater Schlüssel für die Public-Key-Anmeldung.
    pub key: PrivateKey,
    /// Wie der Host-Key des Servers geprüft wird (Pflicht, es gibt keinen Standard).
    pub host_key: HostKeyCheck,
    /// Obergrenze für gesammelte Daten (stdout + stderr eines `exec`, `Sftp::read`);
    /// danach `Error::OutputTooLarge`.
    pub max_output: usize,
    /// Nach so vielen übertragenen Bytes (gesendet + empfangen) tauschen wir die Schlüssel.
    pub rekey_after_bytes: u64,
    /// Spätestens nach dieser Zeit tauschen wir die Schlüssel.
    pub rekey_interval: Duration,
    /// Frist für Verbindungsaufbau, Handshake und Anmeldung zusammen.
    pub timeout: Duration,
    /// Lebenszeichen-Prüfung: Intervall und erlaubte Anzahl ausgebliebener Intervalle.
    pub keepalive: Option<(Duration, u32)>,
}

impl Config {
    /// Neue Konfiguration; Fristen und Grenzen haben sinnvolle Standardwerte.
    pub fn new(user: impl Into<String>, key: PrivateKey, host_key: HostKeyCheck) -> Self {
        Self {
            user: user.into(),
            key,
            host_key,
            max_output: DEFAULT_MAX_OUTPUT,
            rekey_after_bytes: DEFAULT_REKEY_BYTES,
            rekey_interval: DEFAULT_REKEY_INTERVAL,
            timeout: DEFAULT_TIMEOUT,
            keepalive: None,
        }
    }

    /// Setzt die Obergrenze für gesammelte Daten (siehe das Feld `max_output`).
    pub fn max_output(mut self, bytes: usize) -> Self {
        self.max_output = bytes;
        self
    }

    /// Schlüsselwechsel nach dieser Datenmenge (Standard 1 GiB, wie OpenSSH).
    pub fn rekey_after_bytes(mut self, bytes: u64) -> Self {
        self.rekey_after_bytes = bytes;
        self
    }

    /// Schlüsselwechsel spätestens nach dieser Zeit (Standard 1 Stunde).
    pub fn rekey_interval(mut self, interval: Duration) -> Self {
        self.rekey_interval = interval;
        self
    }

    /// Frist für TCP-Verbindung, Handshake und Anmeldung zusammen (Standard 30 s);
    /// danach `Error::Timeout`.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Schickt alle `interval` eine Anfrage an den Server. Kommt `max_missed` Intervalle
    /// lang gar nichts an, gilt die Verbindung als tot (`Error::ConnectionLost`) und alle
    /// laufenden Operationen enden. Standardmäßig aus.
    pub fn keepalive(mut self, interval: Duration, max_missed: u32) -> Self {
        self.keepalive = Some((interval, max_missed));
        self
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("user", &self.user)
            .field("key", &self.key)
            .field("host_key", &self.host_key)
            .field("max_output", &self.max_output)
            .field("rekey_after_bytes", &self.rekey_after_bytes)
            .field("rekey_interval", &self.rekey_interval)
            .field("timeout", &self.timeout)
            .field("keepalive", &self.keepalive)
            .finish()
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("server_banner", &self.server_banner)
            .field("host_key_fingerprint", &self.host_key_fingerprint)
            .finish_non_exhaustive()
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
    /// Verbindet per TCP, führt Handshake und Anmeldung aus (höchstens `Config::timeout`).
    pub async fn connect(addr: impl ToSocketAddrs, config: Config) -> Result<Self> {
        let limit = config.timeout;
        let setup = async {
            let stream = TcpStream::connect(addr).await?;
            // Viele kleine Pakete (Tastendrücke, Schlüsselaustausch): Nagle würde sie um
            // Dutzende Millisekunden verzögern.
            stream.set_nodelay(true)?;
            Self::establish(stream, config).await
        };
        tokio::time::timeout(limit, setup)
            .await
            .map_err(|_| Error::Timeout("connect"))?
    }

    /// Wie [`Session::connect`], aber über einen bereits offenen Stream (die Frist
    /// gilt für Handshake und Anmeldung). Muss innerhalb einer Tokio-Runtime laufen.
    pub async fn from_stream<S>(stream: S, config: Config) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let limit = config.timeout;
        tokio::time::timeout(limit, Self::establish(stream, config))
            .await
            .map_err(|_| Error::Timeout("handshake"))?
    }

    async fn establish<S>(stream: S, config: Config) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut transport = Transport::connect(stream, &config.host_key).await?;
        authenticate(&mut transport, &config.user, &config.key).await?;
        let server_banner = transport.server_banner().to_owned();
        let host_key_fingerprint = transport.host_key_fingerprint().to_owned();
        let (recv, send, rekey_context) = transport.into_split();
        Ok(Self {
            handle: mux::spawn(
                recv,
                send,
                rekey_context,
                mux::RekeyLimits {
                    bytes: config.rekey_after_bytes,
                    interval: config.rekey_interval,
                },
                config
                    .keepalive
                    .map(|(interval, max_missed)| mux::Keepalive {
                        interval,
                        max_missed,
                    }),
            ),
            max_output: config.max_output,
            server_banner,
            host_key_fingerprint,
        })
    }

    /// Anzahl der Schlüsselwechsel seit dem Verbindungsaufbau (zur Diagnose).
    pub fn rekey_count(&self) -> u64 {
        self.handle.rekey_count()
    }

    /// Versionszeile des Servers, z.B. `SSH-2.0-OpenSSH_9.6`.
    pub fn server_banner(&self) -> &str {
        &self.server_banner
    }

    /// Fingerprint (`SHA256:...`) des Host-Keys dieser Verbindung.
    pub fn host_key_fingerprint(&self) -> &str {
        &self.host_key_fingerprint
    }
}
