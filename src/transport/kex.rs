//! `curve25519-sha256` (RFC 8731) mit `ssh-ed25519`-Host-Key (RFC 8709).

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::cipher::KEY_LEN;
use super::kexinit::HOST_KEY_ALGORITHM;
use crate::error::{Error, Result};
use crate::wire::{Reader, Writer};

pub const MSG_KEX_ECDH_INIT: u8 = 30;
pub const MSG_KEX_ECDH_REPLY: u8 = 31;

/// Gemeinsames Geheimnis K (32 Bytes, wie von X25519 geliefert).
pub struct SharedSecret(Zeroizing<[u8; 32]>);

/// Ephemeres Schlüsselpaar des Clients.
pub struct EcdhClient {
    secret: StaticSecret,
    public: PublicKey,
}

impl EcdhClient {
    pub fn new() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut seed[..]).map_err(|_| Error::ProtocolViolation("rng failure"))?;
        Ok(Self::from_seed(*seed))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Berechnet K. Ein Peer-Punkt kleiner Ordnung (K = 0) wird abgelehnt.
    pub fn diffie_hellman(&self, peer_public: &[u8]) -> Result<SharedSecret> {
        let peer: [u8; 32] = peer_public
            .try_into()
            .map_err(|_| Error::ProtocolViolation("bad ecdh public key length"))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(Error::ProtocolViolation("non-contributory ecdh secret"));
        }
        Ok(SharedSecret(Zeroizing::new(shared.to_bytes())))
    }
}

pub fn ecdh_init_message(client_public: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(MSG_KEX_ECDH_INIT).put_string(client_public);
    w.into_vec()
}

/// Inhalt von SSH_MSG_KEX_ECDH_REPLY.
pub struct EcdhReply<'a> {
    pub host_key_blob: &'a [u8],
    pub server_public: &'a [u8],
    pub signature_blob: &'a [u8],
}

pub fn parse_ecdh_reply(payload: &[u8]) -> Result<EcdhReply<'_>> {
    let mut r = Reader::new(payload);
    if r.get_u8()? != MSG_KEX_ECDH_REPLY {
        return Err(Error::ProtocolViolation("expected KEX_ECDH_REPLY"));
    }
    let reply = EcdhReply {
        host_key_blob: r.get_string()?,
        server_public: r.get_string()?,
        signature_blob: r.get_string()?,
    };
    r.finish()?;
    Ok(reply)
}

/// Eingaben des Exchange-Hash H (RFC 8731 §3.1 / RFC 4253 §8).
pub struct HashInput<'a> {
    pub client_banner: &'a str,
    pub server_banner: &'a str,
    pub client_kexinit: &'a [u8],
    pub server_kexinit: &'a [u8],
    pub host_key_blob: &'a [u8],
    pub client_public: &'a [u8],
    pub server_public: &'a [u8],
}

pub fn exchange_hash(i: &HashInput<'_>, k: &SharedSecret) -> [u8; 32] {
    let mut w = Writer::new();
    w.put_string(i.client_banner.as_bytes())
        .put_string(i.server_banner.as_bytes())
        .put_string(i.client_kexinit)
        .put_string(i.server_kexinit)
        .put_string(i.host_key_blob)
        .put_string(i.client_public)
        .put_string(i.server_public)
        .put_mpint(&k.0[..]);
    Sha256::digest(w.as_slice()).into()
}

/// Schlüssel je Richtung (jeweils 64 Bytes für ChaCha20-Poly1305).
pub struct DerivedKeys {
    pub client_to_server: Zeroizing<[u8; KEY_LEN]>,
    pub server_to_client: Zeroizing<[u8; KEY_LEN]>,
}

/// Schlüsselableitung nach RFC 4253 §7.2: 'C' (Client->Server) und 'D' (Server->Client).
pub fn derive_keys(k: &SharedSecret, h: &[u8; 32], session_id: &[u8; 32]) -> DerivedKeys {
    let mut k_enc = Writer::new();
    k_enc.put_mpint(&k.0[..]);
    let derive = |letter: u8| {
        let first: [u8; 32] = Sha256::new()
            .chain_update(k_enc.as_slice())
            .chain_update(h)
            .chain_update([letter])
            .chain_update(session_id)
            .finalize()
            .into();
        let second: [u8; 32] = Sha256::new()
            .chain_update(k_enc.as_slice())
            .chain_update(h)
            .chain_update(first)
            .finalize()
            .into();
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key[..32].copy_from_slice(&first);
        key[32..].copy_from_slice(&second);
        key
    };
    DerivedKeys {
        client_to_server: derive(b'C'),
        server_to_client: derive(b'D'),
    }
}

fn parse_host_key(blob: &[u8]) -> Result<VerifyingKey> {
    let mut r = Reader::new(blob);
    if r.get_str()? != HOST_KEY_ALGORITHM {
        return Err(Error::ProtocolViolation("unexpected host key algorithm"));
    }
    let key: [u8; 32] = r
        .get_string()?
        .try_into()
        .map_err(|_| Error::Malformed("bad ed25519 key length"))?;
    r.finish()?;
    VerifyingKey::from_bytes(&key).map_err(|_| Error::Malformed("invalid ed25519 key"))
}

/// Prüft die Server-Signatur über H mit dem übermittelten Host-Key.
pub fn verify_signature(host_key_blob: &[u8], h: &[u8; 32], signature_blob: &[u8]) -> Result<()> {
    let key = parse_host_key(host_key_blob)?;
    let mut r = Reader::new(signature_blob);
    if r.get_str()? != HOST_KEY_ALGORITHM {
        return Err(Error::ProtocolViolation("unexpected signature algorithm"));
    }
    let sig: [u8; 64] = r
        .get_string()?
        .try_into()
        .map_err(|_| Error::BadSignature)?;
    r.finish()?;
    key.verify_strict(h, &Signature::from_bytes(&sig))
        .map_err(|_| Error::BadSignature)
}
