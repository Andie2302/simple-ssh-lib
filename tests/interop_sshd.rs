//! Handshake gegen einen echten OpenSSH-Server. Überspringt sich, wenn `sshd`
//! nicht installiert ist (Debian/Ubuntu: `apt install openssh-server`).

mod common;

use common::TestSshd;
use simple_ssh_lib::Error;
use simple_ssh_lib::transport::{HostKeyCheck, Transport};
use tokio::net::TcpStream;

macro_rules! sshd_or_skip {
    () => {
        match TestSshd::start() {
            Some(s) => s,
            None => {
                eprintln!("sshd/ssh-keygen not available, skipping");
                return;
            }
        }
    };
}

#[tokio::test]
async fn handshake_with_openssh() {
    let sshd = sshd_or_skip!();
    let stream = TcpStream::connect(sshd.addr()).await.unwrap();
    let mut t = Transport::connect(stream, &HostKeyCheck::Fingerprint(sshd.fingerprint.clone()))
        .await
        .unwrap();
    assert!(t.is_encrypted());
    assert!(t.server_banner().starts_with("SSH-2.0-OpenSSH"));
    assert_eq!(t.host_key_fingerprint(), sshd.fingerprint);
    // Beweist, dass Verschlüsselung und Sequenznummern in beide Richtungen stimmen.
    t.request_service("ssh-userauth").await.unwrap();
}

#[tokio::test]
async fn wrong_fingerprint_is_rejected_by_openssh_handshake() {
    let sshd = sshd_or_skip!();
    let stream = TcpStream::connect(sshd.addr()).await.unwrap();
    let err = Transport::connect(stream, &HostKeyCheck::Fingerprint("SHA256:wrong".into()))
        .await
        .err()
        .unwrap();
    assert!(
        matches!(err, Error::HostKeyRejected { ref fingerprint } if *fingerprint == sshd.fingerprint)
    );
}
