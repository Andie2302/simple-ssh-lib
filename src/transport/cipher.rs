//! `chacha20-poly1305@openssh.com` (PROTOCOL.chacha20poly1305 von OpenSSH).
//!
//! Der 64-Byte-Schlüssel besteht aus K_2 (Bytes 0..32, Payload + Poly1305-Schlüssel)
//! und K_1 (Bytes 32..64, nur Längenfeld). Als Nonce dient die 64-Bit-Sequenznummer.
//! Weil der Blockzähler innerhalb eines Pakets nie 2^32 erreicht, ist das mit
//! der IETF-Variante (32-Bit-Zähler, 96-Bit-Nonce mit vier führenden Nullbytes)
//! identisch.
//!
//! Paketaufbau auf dem Draht: `enc(length:4) | enc(padlen | payload | padding) | tag:16`.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;
use zeroize::Zeroizing;

use super::packet::{MAX_PACKET_LEN, unpad};
use crate::error::{Error, Result};

pub const KEY_LEN: usize = 64;
pub const TAG_LEN: usize = 16;
const BLOCK: usize = 8;
const MIN_PADDING: usize = 4;

pub struct ChaChaPoly {
    k_main: Zeroizing<[u8; 32]>,
    k_len: Zeroizing<[u8; 32]>,
}

fn stream(key: &[u8; 32], seq: u32) -> ChaCha20 {
    let mut nonce = [0u8; 12];
    nonce[8..].copy_from_slice(&seq.to_be_bytes());
    ChaCha20::new(key.into(), &nonce.into())
}

impl ChaChaPoly {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        let mut k_main = Zeroizing::new([0u8; 32]);
        let mut k_len = Zeroizing::new([0u8; 32]);
        k_main.copy_from_slice(&key[..32]);
        k_len.copy_from_slice(&key[32..]);
        Self { k_main, k_len }
    }

    fn tag(&self, seq: u32, authenticated: &[u8]) -> [u8; TAG_LEN] {
        let mut poly_key = Zeroizing::new([0u8; 32]);
        stream(&self.k_main, seq).apply_keystream(&mut poly_key[..]);
        let tag = Poly1305::new((&*poly_key).into()).compute_unpadded(authenticated);
        tag.into()
    }

    /// Verschlüsselt `payload` zu einem vollständigen Paket (inkl. Tag).
    pub fn seal(&self, seq: u32, payload: &[u8]) -> Result<Vec<u8>> {
        self.seal_with_limit(seq, payload, MAX_PACKET_LEN)
    }

    /// Wie [`seal`](Self::seal) mit anderer Größengrenze (nur für Tests mit großen Servern).
    #[doc(hidden)]
    pub fn seal_with_limit(&self, seq: u32, payload: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut pad_len = BLOCK - (1 + payload.len()) % BLOCK;
        if pad_len < MIN_PADDING {
            pad_len += BLOCK;
        }
        let packet_length = 1 + payload.len() + pad_len;
        if packet_length > limit {
            return Err(Error::InvalidPacket("packet too large"));
        }

        let mut out = Vec::with_capacity(4 + packet_length + TAG_LEN);
        out.extend_from_slice(&(packet_length as u32).to_be_bytes());
        out.push(pad_len as u8);
        out.extend_from_slice(payload);
        let pad_start = out.len();
        out.resize(pad_start + pad_len, 0);
        getrandom::fill(&mut out[pad_start..]).map_err(|_| Error::InvalidPacket("rng failure"))?;

        stream(&self.k_len, seq).apply_keystream(&mut out[..4]);
        let mut body = stream(&self.k_main, seq);
        body.seek(64u64);
        body.apply_keystream(&mut out[4..]);

        let tag = self.tag(seq, &out);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Entschlüsselt das Längenfeld. Der Wert ist erst nach `open` vertrauenswürdig.
    pub fn decrypt_len(&self, seq: u32, enc_len: &[u8; 4]) -> u32 {
        let mut len = *enc_len;
        stream(&self.k_len, seq).apply_keystream(&mut len);
        u32::from_be_bytes(len)
    }

    /// Prüft den Tag und entschlüsselt. `enc_len` und `enc_body` stammen vom Draht.
    pub fn open(
        &self,
        seq: u32,
        enc_len: &[u8; 4],
        enc_body: &[u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<Vec<u8>> {
        let mut authenticated = Vec::with_capacity(4 + enc_body.len());
        authenticated.extend_from_slice(enc_len);
        authenticated.extend_from_slice(enc_body);
        let expected = self.tag(seq, &authenticated);
        let diff = expected
            .iter()
            .zip(tag)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff != 0 {
            return Err(Error::MacFailure);
        }

        let mut body = enc_body.to_vec();
        let mut s = stream(&self.k_main, seq);
        s.seek(64u64);
        s.apply_keystream(&mut body);
        if !body.len().is_multiple_of(BLOCK) {
            return Err(Error::InvalidPacket("bad packet length"));
        }
        Ok(unpad(&body)?.to_vec())
    }
}
