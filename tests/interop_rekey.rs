//! Schlüsselwechsel unter Last gegen einen echten OpenSSH-Server (Skip ohne sshd).
//!
//! Beide Richtungen werden geprüft: Wir lösen den Wechsel selbst aus (kleine
//! `rekey_after_bytes`) oder der Server (`RekeyLimit` in der sshd-Konfiguration).
//! Daten müssen dabei byte-genau ankommen, nichts darf hängen.

mod common;

use std::time::Duration;

use common::{Options, Scratch, TestSshd};
use simple_ssh_lib::keys::PrivateKey;
use simple_ssh_lib::transport::HostKeyCheck;
use simple_ssh_lib::{Config, Pty, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(90);

fn config(sshd: &TestSshd) -> Config {
    let key = PrivateKey::from_openssh(&sshd.key_plain, None).unwrap();
    Config::new(
        &sshd.user,
        key,
        HostKeyCheck::Fingerprint(sshd.fingerprint.clone()),
    )
}

macro_rules! sshd_or_skip {
    ($opts:expr) => {
        match TestSshd::start_with($opts) {
            Some(s) => s,
            None => {
                eprintln!("sshd/sftp-server not available, skipping");
                return;
            }
        }
    };
}

fn pattern(len: usize, salt: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(131).wrapping_add(salt) % 251) as u8)
        .collect()
}

#[tokio::test]
async fn client_initiated_rekeying_keeps_data_intact() {
    let sshd = sshd_or_skip!(Options::default());
    let scratch = Scratch::new("rekey-client");
    let session = Session::connect(sshd.addr(), config(&sshd).rekey_after_bytes(100_000))
        .await
        .unwrap();
    assert_eq!(session.rekey_count(), 0);

    let data = pattern(5_000_000, 1);
    let out = timeout(LIMIT, session.exec_with_input("cat", &data))
        .await
        .expect("hung")
        .unwrap();
    assert!(out.stdout == data, "exec data corrupted");
    assert!(
        session.rekey_count() >= 5,
        "only {} rekeys",
        session.rekey_count()
    );

    let sftp = session.sftp().await.unwrap();
    let path = scratch.path("f.bin");
    timeout(LIMIT, sftp.write(&path, &data))
        .await
        .expect("hung")
        .unwrap();
    assert!(std::fs::read(&path).unwrap() == data, "upload corrupted");
    assert!(
        timeout(LIMIT, sftp.read(&path))
            .await
            .expect("hung")
            .unwrap()
            == data,
        "download corrupted"
    );

    assert_eq!(
        session.exec("echo still-fine").await.unwrap().stdout,
        b"still-fine\n"
    );
}

#[tokio::test]
async fn server_initiated_rekeying_keeps_data_intact() {
    let sshd = sshd_or_skip!(Options {
        rekey_limit: Some("64K"),
        ..Options::default()
    });
    let scratch = Scratch::new("rekey-server");
    // Client-Schwelle bleibt beim Standard; wechseln wird der Server.
    let session = Session::connect(sshd.addr(), config(&sshd)).await.unwrap();

    let data = pattern(3_000_000, 2);
    let out = timeout(LIMIT, session.exec_with_input("cat", &data))
        .await
        .expect("hung")
        .unwrap();
    assert!(out.stdout == data, "exec data corrupted");
    assert!(
        session.rekey_count() >= 3,
        "only {} rekeys",
        session.rekey_count()
    );

    let sftp = session.sftp().await.unwrap();
    let path = scratch.path("g.bin");
    timeout(LIMIT, sftp.write(&path, &data))
        .await
        .expect("hung")
        .unwrap();
    assert!(
        timeout(LIMIT, sftp.read(&path))
            .await
            .expect("hung")
            .unwrap()
            == data
    );
    assert_eq!(session.exec("echo ok").await.unwrap().stdout, b"ok\n");
}

#[tokio::test]
async fn both_sides_rekeying_with_parallel_channels() {
    let sshd = sshd_or_skip!(Options {
        rekey_limit: Some("96K"),
        ..Options::default()
    });
    let scratch = Scratch::new("rekey-both");
    let session = Session::connect(sshd.addr(), config(&sshd).rekey_after_bytes(80_000))
        .await
        .unwrap();
    let sftp = session.sftp().await.unwrap();

    for round in 0..4usize {
        let a = pattern(1_500_000, round);
        let b = pattern(1_200_000, round + 10);
        let path = scratch.path(&format!("p{round}"));
        let mut shell = session.shell(Pty::default()).await.unwrap();

        let shell_work = async {
            shell
                .write_all(format!("echo shell-round-{round}\n").as_bytes())
                .await
                .unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            while !String::from_utf8_lossy(&seen).contains(&format!("shell-round-{round}")) {
                let n = shell.read(&mut buf).await.unwrap();
                assert!(n > 0);
                seen.extend_from_slice(&buf[..n]);
            }
        };
        let (exec, sftp_roundtrip, ()) = timeout(LIMIT, async {
            tokio::join!(
                session.exec_with_input("cat", &a),
                async {
                    sftp.write(&path, &b).await.unwrap();
                    sftp.read(&path).await.unwrap()
                },
                shell_work
            )
        })
        .await
        .expect("hung during parallel rekeying");
        assert!(
            exec.unwrap().stdout == a,
            "round {round}: exec data corrupted"
        );
        assert!(sftp_roundtrip == b, "round {round}: sftp data corrupted");
    }
    assert!(
        session.rekey_count() >= 10,
        "only {} rekeys",
        session.rekey_count()
    );
    assert_eq!(session.exec("echo end").await.unwrap().stdout, b"end\n");
}

#[tokio::test]
async fn time_based_rekey_interval_is_honoured() {
    let sshd = sshd_or_skip!(Options::default());
    let session = Session::connect(
        sshd.addr(),
        config(&sshd).rekey_interval(Duration::from_millis(300)),
    )
    .await
    .unwrap();
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(session.exec("echo t").await.unwrap().stdout, b"t\n");
    }
    assert!(
        session.rekey_count() >= 3,
        "only {} rekeys",
        session.rekey_count()
    );
}
