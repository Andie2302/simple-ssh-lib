//! Kleine, async SSH-Client-Library mit festem Algorithmensatz.
//!
//! Aktueller Stand: Wire-Format, Handshake, Private Keys, Public-Key-Anmeldung und `exec`, Shell und SFTP.

pub mod auth;
pub mod connection;
pub mod error;
pub mod keys;
pub mod sftp;
pub mod transport;
pub mod wire;

pub use connection::{Config, ExecOutput, ExitStatus, Pty, Session, Shell};
pub use error::{Error, Result};
pub use sftp::Sftp;
