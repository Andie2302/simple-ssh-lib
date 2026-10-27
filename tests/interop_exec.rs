//! `exec` gegen einen echten OpenSSH-Server. Überspringt sich ohne `sshd`.

mod common;

use common::TestSshd;
use simple_ssh_lib::keys::PrivateKey;
use simple_ssh_lib::transport::HostKeyCheck;
use simple_ssh_lib::{Config, Error, ExitStatus, Session};
use tokio::net::TcpStream;

fn config(sshd: &TestSshd) -> Config {
    let key = PrivateKey::from_openssh(&sshd.key_plain, None).unwrap();
    Config::new(
        &sshd.user,
        key,
        HostKeyCheck::Fingerprint(sshd.fingerprint.clone()),
    )
}

async fn session(sshd: &TestSshd) -> Session<TcpStream> {
    Session::connect(sshd.addr(), config(sshd)).await.unwrap()
}

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
async fn captures_stdout_and_exit_code() {
    let sshd = sshd_or_skip!();
    let mut s = session(&sshd).await;
    let out = s.exec("echo hello; echo world").await.unwrap();
    assert_eq!(out.stdout, b"hello\nworld\n");
    assert!(out.stderr.is_empty());
    assert_eq!(out.exit, ExitStatus::Code(0));
    assert!(out.success());
}

#[tokio::test]
async fn separates_stderr_and_reports_failure() {
    let sshd = sshd_or_skip!();
    let mut s = session(&sshd).await;
    let out = s.exec("echo out; echo err >&2; exit 3").await.unwrap();
    assert_eq!(out.stdout, b"out\n");
    assert_eq!(out.stderr, b"err\n");
    assert_eq!(out.exit, ExitStatus::Code(3));
    assert!(!out.success());
}

#[tokio::test]
async fn reports_termination_by_signal() {
    let sshd = sshd_or_skip!();
    let mut s = session(&sshd).await;
    let out = s.exec("kill -9 $$").await.unwrap();
    assert_eq!(out.exit, ExitStatus::Signal("KILL".into()));
}

#[tokio::test]
async fn stdin_is_closed_so_readers_finish() {
    let sshd = sshd_or_skip!();
    let mut s = session(&sshd).await;
    let out = s.exec("cat; echo done").await.unwrap();
    assert_eq!(out.stdout, b"done\n");
}

#[tokio::test]
async fn large_output_exercises_window_adjust() {
    let sshd = sshd_or_skip!();
    let mut s = session(&sshd).await;
    // 6 MB sind deutlich mehr als das 2-MiB-Fenster.
    let out = s.exec("head -c 6000000 /dev/zero").await.unwrap();
    assert_eq!(out.stdout.len(), 6_000_000);
    assert!(out.stdout.iter().all(|&b| b == 0));
    assert!(out.success());
}

#[tokio::test]
async fn several_commands_on_one_session() {
    let sshd = sshd_or_skip!();
    let mut s = session(&sshd).await;
    for i in 0..5 {
        let out = s.exec(&format!("echo run-{i}")).await.unwrap();
        assert_eq!(out.stdout, format!("run-{i}\n").into_bytes());
    }
}

#[tokio::test]
async fn output_limit_is_enforced_and_session_stays_usable() {
    let sshd = sshd_or_skip!();
    let mut s = Session::connect(sshd.addr(), config(&sshd).max_output(1_000_000))
        .await
        .unwrap();
    let err = s.exec("head -c 5000000 /dev/zero").await.unwrap_err();
    assert!(matches!(err, Error::OutputTooLarge), "got {err:?}");
    let out = s.exec("echo still alive").await.unwrap();
    assert_eq!(out.stdout, b"still alive\n");
}

#[tokio::test]
async fn unknown_command_is_a_normal_exit_code() {
    let sshd = sshd_or_skip!();
    let mut s = session(&sshd).await;
    let out = s.exec("definitely-not-a-command-xyz").await.unwrap();
    assert_eq!(out.exit, ExitStatus::Code(127));
    assert!(!out.stderr.is_empty());
}
