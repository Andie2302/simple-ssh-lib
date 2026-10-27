//! Kleine, asynchrone SSH-Client-Bibliothek mit festem Algorithmensatz – nach dem Vorbild
//! von WireGuard: wenig Funktionen, keine Verhandlung, klare Fehler statt Fallbacks.
//!
//! # Funktionsumfang
//!
//! * Befehle ausführen ([`Session::exec`], [`Session::exec_with_input`])
//! * Interaktive Shell mit Pseudo-Terminal ([`Session::shell`], [`Shell`])
//! * SFTP Version 3 ([`Session::sftp`], [`Sftp`])
//! * Schlüsselwechsel (Rekeying), Fristen und Keepalive
//!
//! # Sicherheitsmodell
//!
//! Es gibt genau einen Satz von Algorithmen; bietet der Server ihn nicht an, bricht die
//! Verbindung mit [`Error::NoCommonAlgorithm`] ab:
//!
//! | Zweck | Algorithmus |
//! |---|---|
//! | Schlüsselaustausch | `curve25519-sha256` |
//! | Host-Key | `ssh-ed25519` |
//! | Verschlüsselung und Integrität | `chacha20-poly1305@openssh.com` |
//! | Kompression | keine |
//! | Anmeldung | nur `publickey` (ed25519) |
//!
//! * Der Host-Key des Servers **muss** geprüft werden ([`HostKeyCheck`]); es gibt keinen
//!   „alles akzeptieren“-Standard. Beim Schlüsselwechsel muss derselbe Host-Key kommen.
//! * Strict KEX (Schutz gegen den Terrapin-Angriff) ist Pflicht für den Server.
//! * Kein Passwort-Login, kein Agent, kein Forwarding, kein SCP.
//! * Private Keys im OpenSSH-Format (ed25519), auch mit Passphrase (`aes256-ctr` + `bcrypt`).
//! * Das Paket enthält keinen `unsafe`-Code und kein OpenSSL.
//!
//! # Beispiel
//!
//! ```no_run
//! use simple_ssh_lib::{Config, HostKeyCheck, Pty, PrivateKey, Session};
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! # async fn demo() -> simple_ssh_lib::Result<()> {
//! // Private Key laden (Passphrase nur bei verschlüsselten Keys angeben).
//! let pem = std::fs::read_to_string("/home/ich/.ssh/id_ed25519")?;
//! let key = PrivateKey::from_openssh(&pem, None)?;
//!
//! // Den Fingerprint bekommst du auf einem vertrauenswürdigen Weg, z.B. mit
//! // `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` auf dem Server.
//! let config = Config::new("ich", key, HostKeyCheck::Fingerprint("SHA256:...".into()));
//! let session = Session::connect("server.example:22", config).await?;
//!
//! // Befehl ausführen
//! let out = session.exec("uname -a").await?;
//! println!("{}", String::from_utf8_lossy(&out.stdout));
//!
//! // Interaktive Shell
//! let mut shell = session.shell(Pty::new(120, 40)).await?;
//! shell.write_all(b"echo hallo\nexit\n").await?;
//! let mut ausgabe = Vec::new();
//! shell.read_to_end(&mut ausgabe).await?;
//!
//! // Dateien übertragen
//! let sftp = session.sftp().await?;
//! sftp.write("/tmp/hallo.txt", b"Hallo!").await?;
//! let inhalt = sftp.read("/tmp/hallo.txt").await?;
//! assert_eq!(inhalt, b"Hallo!");
//! # Ok(())
//! # }
//! ```
//!
//! # Fehler und Fristen
//!
//! Alle Operationen liefern [`Result`]. [`Config::timeout`] begrenzt den Verbindungsaufbau,
//! [`Config::keepalive`] erkennt tote Verbindungen. Einzelne Aufrufe lassen sich mit
//! `tokio::time::timeout` begrenzen; sie sind abbruchsicher, die Session bleibt danach
//! benutzbar.
//!
//! # Grenzen
//!
//! * Eine Verbindung = ein Benutzer; mehrere Befehle, Shells und SFTP-Zugriffe laufen
//!   gleichzeitig darüber.
//! * Gesammelte Ausgaben sind durch [`Config::max_output`] begrenzt (Standard 64 MiB).
//! * Nur ed25519; RSA- und ECDSA-Keys werden mit [`Error::UnsupportedKey`] abgelehnt.
//! * Die Module `wire` und `transport::{packet, cipher, kex, ...}` sind Interna ohne
//!   Stabilitätszusage.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod auth;
pub mod connection;
/// Fehlertyp der Bibliothek.
pub mod error;
#[doc(hidden)]
pub mod fuzz_api;
pub mod keys;
pub mod sftp;
pub mod transport;
#[doc(hidden)]
pub mod wire;

pub use connection::{Config, ExecOutput, ExitStatus, Pty, Session, Shell};
pub use error::{Error, Result};
pub use keys::PrivateKey;
pub use sftp::Sftp;
pub use transport::{HostKey, HostKeyCheck};
