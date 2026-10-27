//! Interaktive Shell mit PTY gegen einen echten OpenSSH-Server.

mod common;

use std::time::Duration;

use common::TestSshd;
use simple_ssh_lib::keys::PrivateKey;
use simple_ssh_lib::transport::HostKeyCheck;
use simple_ssh_lib::{Config, ExitStatus, Pty, Session, Shell};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

async fn session(sshd: &TestSshd) -> Session {
    let key = PrivateKey::from_openssh(&sshd.key_plain, None).unwrap();
    let config = Config::new(
        &sshd.user,
        key,
        HostKeyCheck::Fingerprint(sshd.fingerprint.clone()),
    );
    Session::connect(sshd.addr(), config).await.unwrap()
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

/// Liest, bis `needle` im bisher Gelesenen vorkommt.
async fn read_until(shell: &mut Shell, needle: &str) -> String {
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    timeout(Duration::from_secs(10), async {
        while !String::from_utf8_lossy(&seen).contains(needle) {
            let n = shell.read(&mut buf).await.unwrap();
            assert!(
                n > 0,
                "shell closed before `{needle}` appeared: {:?}",
                String::from_utf8_lossy(&seen)
            );
            seen.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timeout waiting for `{needle}`: {:?}",
            String::from_utf8_lossy(&seen)
        )
    });
    String::from_utf8_lossy(&seen).into_owned()
}

#[tokio::test]
async fn runs_commands_and_reports_exit_code() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let mut shell = s.shell(Pty::default()).await.unwrap();
    shell.write_all(b"echo hello-$((20+22))\n").await.unwrap();
    read_until(&mut shell, "hello-42").await;
    shell.write_all(b"exit 7\n").await.unwrap();
    assert_eq!(shell.wait_exit().await.unwrap(), ExitStatus::Code(7));
    assert_eq!(shell.exit_status(), ExitStatus::Code(7));
}

#[tokio::test]
async fn read_returns_eof_after_exit() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let mut shell = s.shell(Pty::default()).await.unwrap();
    shell.write_all(b"echo bye; exit\n").await.unwrap();
    let mut all = Vec::new();
    timeout(Duration::from_secs(10), shell.read_to_end(&mut all))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&all).contains("bye"));
}

#[tokio::test]
async fn pty_is_allocated_with_requested_size_and_resize_works() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let mut shell = s.shell(Pty::new(80, 24)).await.unwrap();

    shell.write_all(b"echo size1=$(stty size)\n").await.unwrap();
    read_until(&mut shell, "size1=24 80").await;

    shell.resize(120, 40).unwrap();
    shell.write_all(b"echo size2=$(stty size)\n").await.unwrap();
    read_until(&mut shell, "size2=40 120").await;

    shell
        .write_all(b"[ -t 0 ] && echo is-a-tty\n")
        .await
        .unwrap();
    read_until(&mut shell, "is-a-tty").await;
}

#[tokio::test]
async fn term_variable_follows_pty_request() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let pty = Pty {
        term: "vt100".into(),
        cols: 80,
        rows: 24,
    };
    let mut shell = s.shell(pty).await.unwrap();
    shell.write_all(b"echo term=$TERM\n").await.unwrap();
    read_until(&mut shell, "term=vt100").await;
}

#[tokio::test]
async fn dropping_a_shell_leaves_the_session_usable() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    {
        let mut shell = s.shell(Pty::default()).await.unwrap();
        shell.write_all(b"echo x\n").await.unwrap();
        read_until(&mut shell, "x").await;
    }
    let out = s.exec("echo after-drop").await.unwrap();
    assert_eq!(out.stdout, b"after-drop\n");
}

#[tokio::test]
async fn shell_and_exec_run_side_by_side() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let mut shell = s.shell(Pty::default()).await.unwrap();
    shell.write_all(b"echo shell-alive\n").await.unwrap();
    let (out, _) = tokio::join!(
        s.exec("echo from-exec"),
        read_until(&mut shell, "shell-alive")
    );
    assert_eq!(out.unwrap().stdout, b"from-exec\n");
}

#[tokio::test]
async fn shell_can_be_split_for_concurrent_io() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let shell = s.shell(Pty::default()).await.unwrap();
    let (mut rd, mut wr) = tokio::io::split(shell);
    let writer = tokio::spawn(async move {
        wr.write_all(b"echo split-ok; exit\n").await.unwrap();
        wr
    });
    let mut all = Vec::new();
    timeout(Duration::from_secs(10), rd.read_to_end(&mut all))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&all).contains("split-ok"));
    let _ = writer.await.unwrap();
}
