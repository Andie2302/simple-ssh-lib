//! Protokoll-Version-Austausch (RFC 4253 §4.2).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

pub const CLIENT_BANNER: &str = "SSH-2.0-simple-ssh-lib_0.1";

/// Banner-Zeile inkl. CRLF darf höchstens 255 Bytes lang sein.
const MAX_BANNER: usize = 255;
/// Der Server darf vor dem Banner Textzeilen senden; wir begrenzen sie.
const MAX_PRELUDE: usize = 64 * 1024;

/// Sendet `our_banner` und liest den Banner des Peers (ohne CRLF).
///
/// Es wird byteweise gelesen, damit keine Bytes des folgenden Pakets
/// verbraucht werden.
pub async fn exchange<S>(stream: &mut S, our_banner: &str) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(format!("{our_banner}\r\n").as_bytes())
        .await?;
    stream.flush().await?;

    let mut consumed = 0usize;
    loop {
        let mut line = Vec::new();
        loop {
            let b = stream.read_u8().await?;
            consumed += 1;
            if b == b'\n' {
                break;
            }
            line.push(b);
            if line.len() > MAX_BANNER || consumed > MAX_PRELUDE {
                return Err(Error::ProtocolViolation("banner line too long"));
            }
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.starts_with(b"SSH-") {
            let banner =
                String::from_utf8(line).map_err(|_| Error::Malformed("banner not utf-8"))?;
            if banner.starts_with("SSH-2.0-") || banner.starts_with("SSH-1.99-") {
                return Ok(banner);
            }
            return Err(Error::ProtocolViolation("unsupported ssh protocol version"));
        }
        if consumed > MAX_PRELUDE {
            return Err(Error::ProtocolViolation("no banner received"));
        }
    }
}
