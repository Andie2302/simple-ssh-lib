use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// Eingabe endet, bevor ein Wert vollständig gelesen werden konnte.
    #[error("unexpected end of data")]
    UnexpectedEof,

    /// Nach dem Lesen einer Nachricht sind noch Bytes übrig.
    #[error("{0} trailing bytes after message")]
    TrailingData(usize),

    /// Ein Wert verletzt das SSH-Wire-Format (z.B. ungültiger mpint, Bool, UTF-8).
    #[error("malformed message: {0}")]
    Malformed(&'static str),

    /// Paket verletzt RFC 4253 §6 (Länge, Padding, Alignment).
    #[error("invalid packet: {0}")]
    InvalidPacket(&'static str),
}
