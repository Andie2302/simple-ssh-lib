//! Kleine, async SSH-Client-Library mit festem Algorithmensatz.
//!
//! Aktueller Stand: Wire-Format, Handshake, Private Keys und Public-Key-Anmeldung.

pub mod auth;
pub mod error;
pub mod keys;
pub mod transport;
pub mod wire;

pub use error::{Error, Result};
