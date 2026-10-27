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

    /// Der Server bietet einen unserer festen Algorithmen nicht an.
    #[error("no common algorithm: {0}")]
    NoCommonAlgorithm(&'static str),

    /// Host-Key wurde von der `HostKeyCheck`-Richtlinie abgelehnt.
    #[error("host key rejected (fingerprint {fingerprint})")]
    HostKeyRejected { fingerprint: String },

    /// Signatur des Servers über den Exchange-Hash ist ungültig.
    #[error("invalid server signature")]
    BadSignature,

    /// Der Peer hat `SSH_MSG_DISCONNECT` geschickt.
    #[error("disconnected by peer (code {code}): {message}")]
    Disconnected { code: u32, message: String },

    /// Authentifizierungs-Tag eines Pakets stimmt nicht.
    #[error("packet authentication failed")]
    MacFailure,

    /// Unerwartete oder verbotene Nachricht im Protokollablauf.
    #[error("protocol violation: {0}")]
    ProtocolViolation(&'static str),

    /// Private Key hat ein Format oder einen Typ, den wir nicht unterstützen.
    #[error("unsupported private key: {0}")]
    UnsupportedKey(&'static str),

    /// Der Private Key ist verschlüsselt, es wurde keine Passphrase angegeben.
    #[error("private key is encrypted, passphrase required")]
    PassphraseRequired,

    /// Entschlüsselung des Private Keys schlug fehl.
    #[error("wrong passphrase")]
    WrongPassphrase,

    /// Der Server hat den Public Key abgelehnt.
    #[error("public key authentication failed")]
    AuthFailed,

    /// Der Server bietet keine Public-Key-Authentifizierung an.
    #[error("server does not offer public key authentication")]
    PublicKeyAuthUnavailable,

    /// Der Server hat das Öffnen eines Channels abgelehnt.
    #[error("channel open failed (reason {reason}): {message}")]
    ChannelOpenFailed { reason: u32, message: String },

    /// Der Server hat den Befehl (`exec`-Request) abgelehnt.
    #[error("server rejected the command")]
    CommandRejected,

    /// Die Ausgabe des Befehls überschritt `Config::max_output`.
    #[error("command output exceeded the configured limit")]
    OutputTooLarge,

    /// Der Server hat einen Channel-Request (z.B. `pty-req`, `shell`) abgelehnt.
    #[error("server rejected request `{0}`")]
    RequestRejected(&'static str),

    /// Die Verbindung ist abgebrochen oder wurde beendet.
    #[error("connection lost: {0}")]
    ConnectionLost(String),
}
