//! Kleine, async SSH-Client-Library mit festem Algorithmensatz.
//!
//! Aktueller Stand: Wire-Format und Packet-Layer (Meilenstein 1).

pub mod error;
pub mod transport;
pub mod wire;

pub use error::{Error, Result};
