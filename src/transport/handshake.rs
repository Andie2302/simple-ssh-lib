//! Client-Handshake: Banner, KEXINIT, ECDH, NEWKEYS (mit strict KEX).

use tokio::io::{AsyncRead, AsyncWrite};

use super::cipher::ChaChaPoly;
use super::kex::{self, EcdhClient, HashInput};
use super::{HostKey, HostKeyCheck, MSG_NEWKEYS, Transport, kexinit, version};
use crate::error::{Error, Result};

impl<S: AsyncRead + AsyncWrite + Unpin> Transport<S> {
    /// Führt den kompletten Handshake aus. Danach sind beide Richtungen verschlüsselt.
    ///
    /// Der Server muss strict KEX (Terrapin-Schutz) anbieten, sonst bricht der
    /// Handshake mit [`Error::NoCommonAlgorithm`] ab.
    pub async fn connect(mut stream: S, host_key_check: &HostKeyCheck) -> Result<Self> {
        let server_banner = version::exchange(&mut stream, version::CLIENT_BANNER).await?;
        let mut t = Self::plain(stream, server_banner);

        // KEXINIT. Strict KEX: es muss das allererste Paket sein.
        let client_kexinit = kexinit::build_client_kexinit()?;
        t.send(&client_kexinit).await?;
        let server_kexinit = t.recv_packet().await?;
        kexinit::check_server_kexinit(&server_kexinit)?;

        // ECDH.
        let ecdh = EcdhClient::new()?;
        let client_public = ecdh.public_bytes();
        t.send(&kex::ecdh_init_message(&client_public)).await?;
        let reply_payload = t.recv_packet().await?;
        let reply = kex::parse_ecdh_reply(&reply_payload)?;

        let secret = ecdh.diffie_hellman(reply.server_public)?;
        let h = kex::exchange_hash(
            &HashInput {
                client_banner: version::CLIENT_BANNER,
                server_banner: &t.server_banner,
                client_kexinit: &client_kexinit,
                server_kexinit: &server_kexinit,
                host_key_blob: reply.host_key_blob,
                client_public: &client_public,
                server_public: reply.server_public,
            },
            &secret,
        );
        kex::verify_signature(reply.host_key_blob, &h, reply.signature_blob)?;

        let host_key = HostKey::from_blob(reply.host_key_blob.to_vec());
        t.host_key_fingerprint = host_key.fingerprint();
        t.session_id = h;
        if !host_key_check.accepts(&host_key) {
            return Err(Error::HostKeyRejected {
                fingerprint: t.host_key_fingerprint.clone(),
            });
        }

        // NEWKEYS in beide Richtungen; strict KEX setzt die Sequenznummern zurück.
        let keys = kex::derive_keys(&secret, &h, &h);
        t.send(&[MSG_NEWKEYS]).await?;
        t.send.cipher = Some(ChaChaPoly::new(&keys.client_to_server));
        t.send.seq = 0;

        let newkeys = t.recv_packet().await?;
        if newkeys != [MSG_NEWKEYS] {
            return Err(Error::ProtocolViolation("expected NEWKEYS"));
        }
        t.recv.cipher = Some(ChaChaPoly::new(&keys.server_to_client));
        t.recv.seq = 0;

        Ok(t)
    }
}
