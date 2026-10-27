//! Fristen und Keepalive. Die ersten Tests brauchen keinen sshd.

mod common;

use std::process::Command;
use std::time::{Duration, Instant};

use common::TestSshd;
use simple_ssh_lib::keys::PrivateKey;
use simple_ssh_lib::transport::HostKeyCheck;
use simple_ssh_lib::{Config, Error, Session};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

const PLAIN_KEY: &str = include_str!("fixtures/ed25519_plain");

fn offline_config() -> Config {
    let key = PrivateKey::from_openssh(PLAIN_KEY, None).unwrap();
    Config::new(
        "nobody",
        key,
        HostKeyCheck::Fingerprint("SHA256:unused".into()),
    )
}

fn sshd_config(sshd: &TestSshd) -> Config {
    let key = PrivateKey::from_openssh(&sshd.key_plain, None).unwrap();
    Config::new(
        &sshd.user,
        key,
        HostKeyCheck::Fingerprint(sshd.fingerprint.clone()),
    )
}

macro_rules! sshd_or_skip {
    () => {
        match TestSshd::start() {
            Some(s) => s,
            None => {
                eprintln!("sshd not available, skipping");
                return;
            }
        }
    };
}

#[tokio::test]
async fn silent_server_triggers_the_connect_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let started = Instant::now();
    let result = Session::connect(addr, offline_config().timeout(Duration::from_millis(300))).await;
    assert!(
        matches!(result, Err(Error::Timeout(_))),
        "{:?}",
        result.err()
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn half_a_banner_followed_by_silence_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"SSH-2.0-Slow").await.unwrap(); // kein Zeilenende
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let result = Session::connect(addr, offline_config().timeout(Duration::from_millis(300))).await;
    assert!(
        matches!(result, Err(Error::Timeout(_))),
        "{:?}",
        result.err()
    );
}

#[tokio::test]
async fn server_that_stops_after_the_banner_times_out() {
    let (client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        server.write_all(b"SSH-2.0-Mute\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let result =
        Session::from_stream(client, offline_config().timeout(Duration::from_millis(300))).await;
    assert!(
        matches!(result, Err(Error::Timeout("handshake"))),
        "{:?}",
        result.err()
    );
}

#[tokio::test]
async fn refused_connection_is_an_io_error_not_a_timeout() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let result = Session::connect(("127.0.0.1", port), offline_config()).await;
    assert!(matches!(result, Err(Error::Io(_))), "{:?}", result.err());
}

#[tokio::test]
async fn healthy_idle_connection_survives_keepalive() {
    let sshd = sshd_or_skip!();
    let session = Session::connect(
        sshd.addr(),
        sshd_config(&sshd).keepalive(Duration::from_millis(200), 2),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(session.exec("echo alive").await.unwrap().stdout, b"alive\n");
}

#[tokio::test]
async fn keepalive_detects_a_frozen_server() {
    let sshd = sshd_or_skip!();
    let session = Session::connect(
        sshd.addr(),
        sshd_config(&sshd).keepalive(Duration::from_millis(300), 2),
    )
    .await
    .unwrap();
    let pid = String::from_utf8(session.exec("echo $PPID").await.unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();

    // Den Prozess der Verbindung einfrieren: Er antwortet nicht mehr, TCP bleibt offen.
    assert!(
        Command::new("kill")
            .args(["-STOP", &pid])
            .status()
            .unwrap()
            .success()
    );
    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(10), session.exec("echo never")).await;
    let _ = Command::new("kill").args(["-KILL", &pid]).status();

    let result = result.expect("keepalive did not end the hanging call");
    assert!(
        matches!(result, Err(Error::ConnectionLost(ref m)) if m.contains("keepalive")),
        "{result:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
    // Danach melden alle weiteren Aufrufe sofort den Verlust.
    assert!(matches!(
        session.exec("echo x").await,
        Err(Error::ConnectionLost(_))
    ));
}

#[tokio::test]
async fn cancelling_a_call_with_a_timeout_keeps_the_session_usable() {
    let sshd = sshd_or_skip!();
    let session = Session::connect(sshd.addr(), sshd_config(&sshd))
        .await
        .unwrap();
    let slow = tokio::time::timeout(
        Duration::from_millis(200),
        session.exec("sleep 5; echo late"),
    )
    .await;
    assert!(slow.is_err(), "the slow command should have been cancelled");
    let out = session.exec("echo next").await.unwrap();
    assert_eq!(out.stdout, b"next\n");
    // Und mehrfach hintereinander, ohne dass Channels hängen bleiben.
    for i in 0..5 {
        let _ = tokio::time::timeout(Duration::from_millis(50), session.exec("sleep 2")).await;
        assert_eq!(
            session.exec(&format!("echo {i}")).await.unwrap().stdout,
            format!("{i}\n").into_bytes()
        );
    }
}
