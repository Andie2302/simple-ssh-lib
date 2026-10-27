//! `ssh-userauth` (RFC 4252), ausschließlich Methode `publickey` mit ed25519.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::keys::PrivateKey;
use crate::transport::Transport;
use crate::wire::{Reader, Writer};

const MSG_USERAUTH_REQUEST: u8 = 50;
const MSG_USERAUTH_FAILURE: u8 = 51;
const MSG_USERAUTH_SUCCESS: u8 = 52;
const MSG_USERAUTH_BANNER: u8 = 53;

const SERVICE: &str = "ssh-connection";
const METHOD: &str = "publickey";
const ALGORITHM: &str = "ssh-ed25519";

/// Meldet `user` mit `key` am Server an.
///
/// Fehler: [`Error::AuthFailed`], wenn der Server den Key nicht akzeptiert,
/// [`Error::PublicKeyAuthUnavailable`], wenn er `publickey` gar nicht anbietet.
pub async fn authenticate<S>(t: &mut Transport<S>, user: &str, key: &PrivateKey) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    t.request_service("ssh-userauth").await?;

    let blob = key.public_blob();
    let signature = key.sign(&signed_data(t.session_id(), user, &blob));
    let mut sig_blob = Writer::new();
    sig_blob
        .put_string(ALGORITHM.as_bytes())
        .put_string(&signature);

    let mut w = Writer::new();
    w.put_u8(MSG_USERAUTH_REQUEST);
    put_request_fields(&mut w, user, &blob);
    w.put_string(sig_blob.as_slice());
    t.send(w.as_slice()).await?;

    loop {
        let reply = t.recv().await?;
        match reply[0] {
            MSG_USERAUTH_SUCCESS => return Ok(()),
            MSG_USERAUTH_BANNER => continue,
            MSG_USERAUTH_FAILURE => {
                let mut r = Reader::new(&reply[1..]);
                let methods = r.get_name_list()?;
                r.get_bool()?; // partial success
                r.finish()?;
                return Err(if methods.contains(&METHOD) {
                    Error::AuthFailed
                } else {
                    Error::PublicKeyAuthUnavailable
                });
            }
            _ => return Err(Error::ProtocolViolation("unexpected message during auth")),
        }
    }
}

/// Felder, die im Request und in den signierten Daten identisch sind.
fn put_request_fields(w: &mut Writer, user: &str, blob: &[u8]) {
    w.put_string(user.as_bytes())
        .put_string(SERVICE.as_bytes())
        .put_string(METHOD.as_bytes())
        .put_bool(true)
        .put_string(ALGORITHM.as_bytes())
        .put_string(blob);
}

/// RFC 4252 §7: `string session_id | byte 50 | <Request-Felder>`.
fn signed_data(session_id: &[u8; 32], user: &str, blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_string(session_id).put_u8(MSG_USERAUTH_REQUEST);
    put_request_fields(&mut w, user, blob);
    w.into_vec()
}
