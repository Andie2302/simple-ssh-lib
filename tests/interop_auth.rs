//! Public-Key-Anmeldung gegen einen echten OpenSSH-Server. Überspringt sich,
//! wenn `sshd` nicht installiert ist.

mod common;

use common::{KEY_PASSPHRASE, Options, TestSshd};
use simple_ssh_lib::Error;
use simple_ssh_lib::auth::authenticate;
use simple_ssh_lib::keys::PrivateKey;
use simple_ssh_lib::transport::{HostKeyCheck, Transport};
use tokio::net::TcpStream;

async fn login(sshd: &TestSshd, user: &str, key: &PrivateKey) -> Result<(), Error> {
    let stream = TcpStream::connect(sshd.addr()).await.unwrap();
    let mut t =
        Transport::connect(stream, &HostKeyCheck::Fingerprint(sshd.fingerprint.clone())).await?;
    authenticate(&mut t, user, key).await
}

macro_rules! sshd_or_skip {
    ($opts:expr) => {
        match TestSshd::start_with($opts) {
            Some(s) => s,
            None => {
                eprintln!("sshd/ssh-keygen not available, skipping");
                return;
            }
        }
    };
}

#[tokio::test]
async fn login_with_unencrypted_key() {
    let sshd = sshd_or_skip!(Options::default());
    let key = PrivateKey::from_openssh(&sshd.key_plain, None).unwrap();
    login(&sshd, &sshd.user, &key).await.unwrap();
}

#[tokio::test]
async fn login_with_passphrase_protected_key() {
    let sshd = sshd_or_skip!(Options::default());
    let key =
        PrivateKey::from_openssh(&sshd.key_encrypted, Some(KEY_PASSPHRASE.as_bytes())).unwrap();
    login(&sshd, &sshd.user, &key).await.unwrap();
}

#[tokio::test]
async fn wrong_passphrase_never_reaches_the_network() {
    let sshd = sshd_or_skip!(Options::default());
    let err = PrivateKey::from_openssh(&sshd.key_encrypted, Some(b"nope")).unwrap_err();
    assert!(matches!(err, Error::WrongPassphrase));
}

#[tokio::test]
async fn unauthorized_key_is_rejected() {
    let sshd = sshd_or_skip!(Options::default());
    let key = PrivateKey::from_openssh(&sshd.key_unauthorized, None).unwrap();
    let err = login(&sshd, &sshd.user, &key).await.unwrap_err();
    assert!(matches!(err, Error::AuthFailed), "got {err:?}");
}

#[tokio::test]
async fn unknown_user_is_rejected() {
    let sshd = sshd_or_skip!(Options::default());
    let key = PrivateKey::from_openssh(&sshd.key_plain, None).unwrap();
    let err = login(&sshd, "nobody-such-user", &key).await.unwrap_err();
    assert!(matches!(err, Error::AuthFailed), "got {err:?}");
}

#[tokio::test]
async fn server_without_publickey_auth() {
    let sshd = sshd_or_skip!(Options { pubkey_auth: false });
    let key = PrivateKey::from_openssh(&sshd.key_plain, None).unwrap();
    let err = login(&sshd, &sshd.user, &key).await.unwrap_err();
    assert!(
        matches!(err, Error::PublicKeyAuthUnavailable),
        "got {err:?}"
    );
}
