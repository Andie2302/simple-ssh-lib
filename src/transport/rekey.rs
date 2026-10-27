//! Schlüsselwechsel während einer laufenden Verbindung (RFC 4253 §9).
//!
//! Der Ablauf selbst (wer wann sendet) liegt im Multiplexer; hier steht nur,
//! was kryptografisch und protokollseitig zu prüfen ist.

use super::hostkey::HostKey;
use super::kex::{self, DerivedKeys, EcdhClient, HashInput};
use super::{kexinit, version};
use crate::error::{Error, Result};

/// Was ein Schlüsselwechsel vom ersten Handshake braucht.
pub struct RekeyContext {
    pub server_banner: String,
    /// Session-ID bleibt für die ganze Verbindung die des ersten Austauschs.
    pub session_id: [u8; 32],
    /// Host-Key des ersten Austauschs; ein Wechsel muss denselben Key liefern.
    pub host_key_blob: Vec<u8>,
}

/// Nachrichtentypen unterhalb von 50 (Transport, Algorithmenwahl, Schlüsselaustausch)
/// dürfen während eines Schlüsselwechsels gesendet werden, alle anderen nicht
/// (RFC 4253 §7.1).
pub const fn is_kex_class(message_type: u8) -> bool {
    message_type < 50
}

/// Client-Zustand zwischen ECDH_INIT und ECDH_REPLY.
pub struct PendingKex {
    ecdh: EcdhClient,
    client_public: [u8; 32],
    our_kexinit: Vec<u8>,
    server_kexinit: Vec<u8>,
}

impl PendingKex {
    /// Prüft das KEXINIT des Servers und liefert die ECDH_INIT-Nachricht.
    pub fn begin(our_kexinit: Vec<u8>, server_kexinit: Vec<u8>) -> Result<(Self, Vec<u8>)> {
        kexinit::check_server_kexinit(&server_kexinit, false)?;
        let ecdh = EcdhClient::new()?;
        let client_public = ecdh.public_bytes();
        let init = kex::ecdh_init_message(&client_public);
        Ok((
            Self {
                ecdh,
                client_public,
                our_kexinit,
                server_kexinit,
            },
            init,
        ))
    }

    /// Wertet ECDH_REPLY aus: Host-Key muss dem ersten entsprechen, die Signatur
    /// über den neuen Exchange-Hash muss stimmen.
    pub fn finish(self, ctx: &RekeyContext, reply_payload: &[u8]) -> Result<DerivedKeys> {
        let reply = kex::parse_ecdh_reply(reply_payload)?;
        if reply.host_key_blob != ctx.host_key_blob.as_slice() {
            return Err(Error::HostKeyRejected {
                fingerprint: HostKey::from_blob(reply.host_key_blob.to_vec()).fingerprint(),
            });
        }
        let secret = self.ecdh.diffie_hellman(reply.server_public)?;
        let h = kex::exchange_hash(
            &HashInput {
                client_banner: version::CLIENT_BANNER,
                server_banner: &ctx.server_banner,
                client_kexinit: &self.our_kexinit,
                server_kexinit: &self.server_kexinit,
                host_key_blob: reply.host_key_blob,
                client_public: &self.client_public,
                server_public: reply.server_public,
            },
            &secret,
        );
        kex::verify_signature(reply.host_key_blob, &h, reply.signature_blob)?;
        Ok(kex::derive_keys(&secret, &h, &ctx.session_id))
    }
}
