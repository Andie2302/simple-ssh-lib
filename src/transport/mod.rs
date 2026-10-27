//! Transport-Schicht (RFC 4253): Version-Austausch, Schlüsselaustausch,
//! verschlüsseltes Paketformat.

pub mod cipher;
mod handshake;
pub mod hostkey;
pub mod kex;
pub mod kexinit;
pub mod packet;
pub mod version;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::wire::Reader;
use cipher::{ChaChaPoly, TAG_LEN};
pub use hostkey::{HostKey, HostKeyCheck};

pub const MSG_DISCONNECT: u8 = 1;
pub const MSG_IGNORE: u8 = 2;
pub const MSG_DEBUG: u8 = 4;
pub const MSG_SERVICE_REQUEST: u8 = 5;
pub const MSG_SERVICE_ACCEPT: u8 = 6;
pub const MSG_NEWKEYS: u8 = 21;

/// Verbindung nach abgeschlossenem Handshake: Pakete laufen verschlüsselt.
pub struct Transport<S> {
    stream: S,
    send_seq: u32,
    recv_seq: u32,
    send_cipher: Option<ChaChaPoly>,
    recv_cipher: Option<ChaChaPoly>,
    server_banner: String,
    host_key_fingerprint: String,
    session_id: [u8; 32],
}

impl<S: AsyncRead + AsyncWrite + Unpin> Transport<S> {
    fn plain(stream: S, server_banner: String) -> Self {
        Self {
            stream,
            send_seq: 0,
            recv_seq: 0,
            send_cipher: None,
            recv_cipher: None,
            server_banner,
            host_key_fingerprint: String::new(),
            session_id: [0; 32],
        }
    }

    pub fn server_banner(&self) -> &str {
        &self.server_banner
    }

    pub fn host_key_fingerprint(&self) -> &str {
        &self.host_key_fingerprint
    }

    /// Session-ID (erster Exchange-Hash); geht in die Signatur der Anmeldung ein.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    pub fn is_encrypted(&self) -> bool {
        self.send_cipher.is_some() && self.recv_cipher.is_some()
    }

    /// Sendet einen Payload (erstes Byte = Nachrichtentyp).
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        let bytes = match &self.send_cipher {
            None => packet::encode(payload)?,
            Some(c) => c.seal(self.send_seq, payload)?,
        };
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        self.send_seq = self.send_seq.wrapping_add(1);
        Ok(())
    }

    /// Empfängt ein Paket; DISCONNECT wird zum Fehler. IGNORE/DEBUG werden
    /// hier nicht gefiltert (siehe [`Transport::recv`]).
    async fn recv_packet(&mut self) -> Result<Vec<u8>> {
        let payload = match &self.recv_cipher {
            None => packet::read_packet(&mut self.stream).await?,
            Some(c) => {
                let mut enc_len = [0u8; 4];
                self.stream.read_exact(&mut enc_len).await?;
                let len = c.decrypt_len(self.recv_seq, &enc_len) as usize;
                if len > packet::MAX_PACKET_LEN {
                    return Err(Error::InvalidPacket("packet too large"));
                }
                let mut enc_body = vec![0u8; len];
                self.stream.read_exact(&mut enc_body).await?;
                let mut tag = [0u8; TAG_LEN];
                self.stream.read_exact(&mut tag).await?;
                c.open(self.recv_seq, &enc_len, &enc_body, &tag)?
            }
        };
        self.recv_seq = self.recv_seq.wrapping_add(1);
        if payload.first() == Some(&MSG_DISCONNECT) {
            let mut r = Reader::new(&payload[1..]);
            let code = r.get_u32()?;
            let message = String::from_utf8_lossy(r.get_string()?).into_owned();
            return Err(Error::Disconnected { code, message });
        }
        if payload.is_empty() {
            return Err(Error::ProtocolViolation("empty packet"));
        }
        Ok(payload)
    }

    /// Empfängt die nächste Nachricht, ohne IGNORE und DEBUG.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        loop {
            let p = self.recv_packet().await?;
            if p[0] != MSG_IGNORE && p[0] != MSG_DEBUG {
                return Ok(p);
            }
        }
    }

    /// `SSH_MSG_SERVICE_REQUEST`, z.B. für `ssh-userauth`.
    pub async fn request_service(&mut self, name: &str) -> Result<()> {
        let mut w = crate::wire::Writer::new();
        w.put_u8(MSG_SERVICE_REQUEST).put_string(name.as_bytes());
        self.send(w.as_slice()).await?;
        let reply = self.recv().await?;
        if reply[0] != MSG_SERVICE_ACCEPT {
            return Err(Error::ProtocolViolation("expected SERVICE_ACCEPT"));
        }
        let mut r = Reader::new(&reply[1..]);
        if r.get_str()? != name {
            return Err(Error::ProtocolViolation("service name mismatch"));
        }
        r.finish()
    }
}
