//! Binary Packet Protocol ohne Verschlüsselung (RFC 4253 §6), wie es vor dem
//! ersten NEWKEYS gilt:
//!
//! ```text
//! uint32 packet_length | byte padding_length | payload | random padding
//! ```
//!
//! `packet_length` zählt alles nach dem Längenfeld. Länge von
//! (padding_length + payload + padding) ist ein Vielfaches von 8, Padding mindestens 4.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

const BLOCK: usize = 8;
const MIN_PADDING: usize = 4;
/// RFC 4253 §6.1: Implementierungen müssen mindestens 35000 Bytes Paket verarbeiten.
pub const MAX_PACKET_LEN: usize = 35_000;

/// Kodiert `payload` mit zufälligem Padding.
pub fn encode(payload: &[u8]) -> Result<Vec<u8>> {
    let mut pad = [0u8; BLOCK + MIN_PADDING];
    getrandom::fill(&mut pad).map_err(|_| Error::InvalidPacket("rng failure"))?;
    encode_with_padding(payload, &pad)
}

/// Wie [`encode`], aber das Padding kommt aus `pad_source` (mind. 11 Bytes).
/// Dient deterministischen Tests.
pub fn encode_with_padding(payload: &[u8], pad_source: &[u8]) -> Result<Vec<u8>> {
    let unpadded = 1 + payload.len();
    let mut pad_len = BLOCK - (4 + unpadded) % BLOCK;
    if pad_len < MIN_PADDING {
        pad_len += BLOCK;
    }
    if pad_source.len() < pad_len {
        return Err(Error::InvalidPacket("padding source too short"));
    }
    let packet_length = unpadded + pad_len;
    if packet_length > MAX_PACKET_LEN {
        return Err(Error::InvalidPacket("packet too large"));
    }
    let mut out = Vec::with_capacity(4 + packet_length);
    out.extend_from_slice(&(packet_length as u32).to_be_bytes());
    out.push(pad_len as u8);
    out.extend_from_slice(payload);
    out.extend_from_slice(&pad_source[..pad_len]);
    Ok(out)
}

/// Prüft `body` (alles nach dem Längenfeld) und gibt den Payload zurück.
pub fn decode_body(body: &[u8]) -> Result<&[u8]> {
    if body.len() < 1 + MIN_PADDING || !(4 + body.len()).is_multiple_of(BLOCK) {
        return Err(Error::InvalidPacket("bad packet length"));
    }
    let pad_len = body[0] as usize;
    if pad_len < MIN_PADDING || pad_len > body.len() - 1 {
        return Err(Error::InvalidPacket("bad padding length"));
    }
    Ok(&body[1..body.len() - pad_len])
}

pub async fn write_packet<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<()> {
    w.write_all(&encode(payload)?).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_packet<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_PACKET_LEN {
        return Err(Error::InvalidPacket("packet too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(decode_body(&body)?.to_vec())
}
