//! Transport-Schicht (RFC 4253): Version-Austausch, Schlüsselaustausch,
//! verschlüsseltes Paketformat.

pub mod cipher;
mod handshake;
pub mod hostkey;
pub mod kex;
pub mod kexinit;
pub mod packet;
pub mod rekey;
pub mod version;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

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

/// Zustand einer Senderichtung: Sequenznummer und (nach NEWKEYS) Chiffre.
#[derive(Default)]
struct SendState {
    seq: u32,
    cipher: Option<ChaChaPoly>,
}

impl SendState {
    async fn send<W: AsyncWrite + Unpin>(&mut self, w: &mut W, payload: &[u8]) -> Result<()> {
        let bytes = match &self.cipher {
            None => packet::encode(payload)?,
            Some(c) => c.seal(self.seq, payload)?,
        };
        w.write_all(&bytes).await?;
        w.flush().await?;
        self.seq = self.seq.wrapping_add(1);
        Ok(())
    }
}

/// Zustand einer Empfangsrichtung.
#[derive(Default)]
struct RecvState {
    seq: u32,
    cipher: Option<ChaChaPoly>,
}

impl RecvState {
    /// Empfängt ein Paket; DISCONNECT wird zum Fehler. IGNORE/DEBUG werden
    /// hier nicht gefiltert (siehe `recv`).
    async fn recv_packet<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> Result<Vec<u8>> {
        let payload = match &self.cipher {
            None => packet::read_packet(r).await?,
            Some(c) => {
                let mut enc_len = [0u8; 4];
                r.read_exact(&mut enc_len).await?;
                let len = c.decrypt_len(self.seq, &enc_len) as usize;
                if len > packet::MAX_PACKET_LEN {
                    return Err(Error::InvalidPacket("packet too large"));
                }
                let mut enc_body = vec![0u8; len];
                r.read_exact(&mut enc_body).await?;
                let mut tag = [0u8; TAG_LEN];
                r.read_exact(&mut tag).await?;
                c.open(self.seq, &enc_len, &enc_body, &tag)?
            }
        };
        self.seq = self.seq.wrapping_add(1);
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

    /// Nächste Nachricht ohne IGNORE und DEBUG.
    async fn recv<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> Result<Vec<u8>> {
        loop {
            let p = self.recv_packet(r).await?;
            if p[0] != MSG_IGNORE && p[0] != MSG_DEBUG {
                return Ok(p);
            }
        }
    }
}

/// Verbindung nach abgeschlossenem Handshake: Pakete laufen verschlüsselt.
pub struct Transport<S> {
    stream: S,
    send: SendState,
    recv: RecvState,
    server_banner: String,
    host_key_fingerprint: String,
    host_key_blob: Vec<u8>,
    session_id: [u8; 32],
}

/// Sendehälfte einer aufgeteilten Verbindung (siehe [`Transport::into_split`]).
pub struct SendHalf<W> {
    stream: W,
    state: SendState,
}

/// Empfangshälfte einer aufgeteilten Verbindung.
pub struct RecvHalf<R> {
    stream: R,
    state: RecvState,
}

impl<W: AsyncWrite + Unpin> SendHalf<W> {
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        self.state.send(&mut self.stream, payload).await
    }

    /// Aktiviert neue Schlüssel für alle folgenden Pakete (Sequenznummer wieder 0,
    /// wie es Strict KEX nach jedem NEWKEYS verlangt).
    pub fn install(&mut self, cipher: ChaChaPoly) {
        self.state.cipher = Some(cipher);
        self.state.seq = 0;
    }
}

impl<R: AsyncRead + Unpin> RecvHalf<R> {
    /// Nächste Nachricht ohne IGNORE und DEBUG; DISCONNECT wird zum Fehler.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        self.state.recv(&mut self.stream).await
    }

    /// Aktiviert neue Schlüssel für alle folgenden Pakete (siehe [`SendHalf::install`]).
    pub fn install(&mut self, cipher: ChaChaPoly) {
        self.state.cipher = Some(cipher);
        self.state.seq = 0;
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Transport<S> {
    fn plain(stream: S, server_banner: String) -> Self {
        Self {
            stream,
            send: SendState::default(),
            recv: RecvState::default(),
            server_banner,
            host_key_fingerprint: String::new(),
            host_key_blob: Vec::new(),
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
        self.send.cipher.is_some() && self.recv.cipher.is_some()
    }

    /// Sendet einen Payload (erstes Byte = Nachrichtentyp).
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        self.send.send(&mut self.stream, payload).await
    }

    async fn recv_packet(&mut self) -> Result<Vec<u8>> {
        self.recv.recv_packet(&mut self.stream).await
    }

    /// Empfängt die nächste Nachricht, ohne IGNORE und DEBUG.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        self.recv.recv(&mut self.stream).await
    }

    /// Teilt die Verbindung, damit gleichzeitig gelesen und geschrieben werden kann.
    /// Der [`rekey::RekeyContext`] enthält, was für spätere Schlüsselwechsel nötig ist.
    pub fn into_split(
        self,
    ) -> (
        RecvHalf<ReadHalf<S>>,
        SendHalf<WriteHalf<S>>,
        rekey::RekeyContext,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        let context = rekey::RekeyContext {
            server_banner: self.server_banner,
            session_id: self.session_id,
            host_key_blob: self.host_key_blob,
        };
        (
            RecvHalf {
                stream: r,
                state: self.recv,
            },
            SendHalf {
                stream: w,
                state: self.send,
            },
            context,
        )
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
