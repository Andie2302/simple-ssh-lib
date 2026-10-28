//! `exec_stream` gegen einen echten OpenSSH-Server (Skip ohne sshd).

mod common;

use std::time::{Duration, Instant};

use common::{Scratch, TestSshd};
use simple_ssh_lib::keys::PrivateKey;
use simple_ssh_lib::transport::HostKeyCheck;
use simple_ssh_lib::{Config, Error, ExecEvent, ExecStream, ExitStatus, Session};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(60);

fn config(sshd: &TestSshd) -> Config {
    let key = PrivateKey::from_openssh(&sshd.key_plain, None).unwrap();
    Config::new(
        &sshd.user,
        key,
        HostKeyCheck::Fingerprint(sshd.fingerprint.clone()),
    )
}

async fn session(sshd: &TestSshd) -> Session {
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

fn pattern(len: usize, salt: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(131).wrapping_add(salt) % 251) as u8)
        .collect()
}

/// Sammelt alles bis zum Ende: (stdout, stderr).
async fn drain(stream: &mut ExecStream) -> (Vec<u8>, Vec<u8>) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    while let Some(ev) = timeout(LIMIT, stream.next()).await.expect("hung").unwrap() {
        match ev {
            ExecEvent::Stdout(d) => out.extend(d),
            ExecEvent::Stderr(d) => err.extend(d),
            _ => unreachable!("neue Ereignisarten gibt es noch nicht"),
        }
    }
    (out, err)
}

#[tokio::test]
async fn output_arrives_while_the_command_is_still_running() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let started = Instant::now();
    let mut stream = s
        .exec_stream("echo first; sleep 1; echo second")
        .await
        .unwrap();
    stream.close_stdin().await.unwrap();

    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(first, ExecEvent::Stdout(b"first\n".to_vec()));
    assert!(
        started.elapsed() < Duration::from_millis(700),
        "first line took {:?}",
        started.elapsed()
    );
    assert_eq!(
        stream.exit_status(),
        ExitStatus::Unknown,
        "Befehl läuft noch"
    );

    let second = stream.next().await.unwrap().unwrap();
    assert_eq!(second, ExecEvent::Stdout(b"second\n".to_vec()));
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert!(stream.next().await.unwrap().is_none());
    assert!(
        stream.next().await.unwrap().is_none(),
        "nach dem Ende bleibt es bei None"
    );
    assert_eq!(stream.exit_status(), ExitStatus::Code(0));
}

#[tokio::test]
async fn stdout_stderr_and_exit_status_are_reported() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;

    let mut stream = s
        .exec_stream("echo out; echo err >&2; exit 3")
        .await
        .unwrap();
    stream.close_stdin().await.unwrap();
    let (out, err) = drain(&mut stream).await;
    assert_eq!(out, b"out\n");
    assert_eq!(err, b"err\n");
    assert_eq!(stream.exit_status(), ExitStatus::Code(3));

    let mut stream = s.exec_stream("kill -9 $$").await.unwrap();
    stream.close_stdin().await.unwrap();
    drain(&mut stream).await;
    assert_eq!(stream.exit_status(), ExitStatus::Signal("KILL".into()));
}

#[tokio::test]
async fn stdin_is_delivered_live() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let mut stream = s.exec_stream("cat").await.unwrap();

    stream.write_stdin(b"hello\n").await.unwrap();
    let echoed = timeout(Duration::from_secs(3), stream.next())
        .await
        .expect("no echo before EOF")
        .unwrap()
        .unwrap();
    assert_eq!(echoed, ExecEvent::Stdout(b"hello\n".to_vec()));

    stream.write_stdin(b"world\n").await.unwrap();
    let echoed = timeout(Duration::from_secs(3), stream.next())
        .await
        .expect("no echo before EOF")
        .unwrap()
        .unwrap();
    assert_eq!(echoed, ExecEvent::Stdout(b"world\n".to_vec()));

    stream.close_stdin().await.unwrap();
    stream.close_stdin().await.unwrap(); // mehrfach ist harmlos
    let (rest, _) = drain(&mut stream).await;
    assert!(rest.is_empty());
    assert_eq!(stream.exit_status(), ExitStatus::Code(0));
    assert!(
        stream.write_stdin(b"too late").await.is_err(),
        "nach EOF ist Schreiben ein Fehler"
    );
}

#[tokio::test]
async fn ten_megabytes_through_cat_in_both_directions() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let data = pattern(10 * 1024 * 1024 + 7, 3);

    let stream = s.exec_stream("cat").await.unwrap();
    let (mut stdin, mut events) = stream.split();
    let feed = data.clone();
    let pump = tokio::spawn(async move {
        stdin.write_all(&feed).await.unwrap();
        stdin.shutdown().await.unwrap();
        stdin
    });
    let mut echoed = Vec::with_capacity(data.len());
    let mut largest = 0;
    while let Some(ev) = timeout(LIMIT, events.next()).await.expect("hung").unwrap() {
        if let ExecEvent::Stdout(d) = ev {
            largest = largest.max(d.len());
            echoed.extend(d);
        }
    }
    let _stdin = pump.await.unwrap();
    assert_eq!(echoed.len(), data.len());
    assert!(echoed == data, "Daten verändert");
    assert!(
        largest <= 32 * 1024,
        "Stücke größer als ein Paket: {largest}"
    );
    assert_eq!(events.exit_status(), ExitStatus::Code(0));
}

#[tokio::test]
async fn thirty_megabytes_stream_without_being_kept_in_memory() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let mut stream = s.exec_stream("head -c 30000000 /dev/zero").await.unwrap();
    stream.close_stdin().await.unwrap();
    let (mut total, mut nonzero) = (0usize, 0usize);
    while let Some(ev) = timeout(LIMIT, stream.next()).await.expect("hung").unwrap() {
        if let ExecEvent::Stdout(d) = ev {
            total += d.len();
            nonzero += d.iter().filter(|&&b| b != 0).count();
        }
    }
    assert_eq!(total, 30_000_000);
    assert_eq!(nonzero, 0);
}

#[tokio::test]
async fn a_slow_reader_holds_the_server_back() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("stream-backpressure");
    let marker = scratch.path("marker");
    let s = session(&sshd).await;
    let command = format!("head -c 60000000 /dev/zero; touch {marker}");
    let mut stream = s.exec_stream(&command).await.unwrap();
    stream.close_stdin().await.unwrap();

    // Ein Stück lesen, dann lange nicht mehr: Der Server darf nur ein Fenster voraus sein.
    assert!(stream.next().await.unwrap().is_some());
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        !std::path::Path::new(&marker).exists(),
        "Befehl lief durch, obwohl niemand las"
    );

    drain(&mut stream).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        std::path::Path::new(&marker).exists(),
        "Befehl wurde nicht fertig"
    );
}

#[tokio::test]
async fn dropping_the_stream_closes_the_channel_and_keeps_the_session() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let stream = s.exec_stream("sleep 30").await.unwrap();
    drop(stream);
    assert_eq!(s.exec("echo ok").await.unwrap().stdout, b"ok\n");

    // Nur die Eingabehälfte fallen lassen: der Befehl sieht kein EOF und läuft weiter.
    let stream = s.exec_stream("cat; echo finished").await.unwrap();
    let (stdin, mut events) = stream.split();
    drop(stdin);
    assert!(
        timeout(Duration::from_millis(500), events.next())
            .await
            .is_err(),
        "kein EOF erwartet"
    );
    drop(events);
    assert_eq!(s.exec("echo still").await.unwrap().stdout, b"still\n");
}

#[tokio::test]
async fn cancelling_next_with_a_timeout_loses_no_data() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let mut stream = s
        .exec_stream("for i in 1 2 3 4; do echo $i; sleep 0.3; done")
        .await
        .unwrap();
    stream.close_stdin().await.unwrap();
    let (_stdin, mut events) = stream.split();

    let mut collected = Vec::new();
    let mut cancelled = 0;
    loop {
        match timeout(Duration::from_millis(40), events.next()).await {
            Err(_) => cancelled += 1,
            Ok(Ok(Some(ExecEvent::Stdout(d)))) => collected.extend(d),
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => break,
            Ok(Err(e)) => panic!("{e}"),
        }
    }
    assert!(
        cancelled >= 3,
        "der Test hätte abbrechen müssen ({cancelled})"
    );
    assert_eq!(collected, b"1\n2\n3\n4\n");
}

#[tokio::test]
async fn connection_loss_ends_the_stream_with_an_error() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let mut stream = s.exec_stream("kill -9 $PPID").await.unwrap();
    stream.close_stdin().await.ok();
    let result = timeout(Duration::from_secs(10), async {
        loop {
            match stream.next().await {
                Ok(Some(_)) => continue,
                other => return other,
            }
        }
    })
    .await
    .expect("stream hung after connection loss");
    assert!(
        matches!(result, Err(Error::ConnectionLost(_))),
        "{result:?}"
    );
    assert!(matches!(
        s.exec("echo x").await,
        Err(Error::ConnectionLost(_))
    ));
}

#[tokio::test]
async fn several_streams_and_an_exec_run_side_by_side() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let started = Instant::now();
    let run = |cmd: &'static str| {
        let s = &s;
        async move {
            let mut st = s.exec_stream(cmd).await.unwrap();
            st.close_stdin().await.unwrap();
            drain(&mut st).await.0
        }
    };
    let (a, b, c) = tokio::join!(run("sleep 1; echo a"), run("sleep 1; echo b"), async {
        s.exec("sleep 1; echo c").await.unwrap().stdout
    });
    assert_eq!(
        (a, b, c),
        (b"a\n".to_vec(), b"b\n".to_vec(), b"c\n".to_vec())
    );
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "liefen nacheinander"
    );
}

#[tokio::test]
async fn key_exchanges_in_the_middle_of_a_stream() {
    let sshd = sshd_or_skip!();
    let s = Session::connect(sshd.addr(), config(&sshd).rekey_after_bytes(64 * 1024))
        .await
        .unwrap();
    let data = pattern(3_000_000, 9);
    let stream = s.exec_stream("cat").await.unwrap();
    let (mut stdin, mut events) = stream.split();
    let feed = data.clone();
    let pump = tokio::spawn(async move {
        stdin.write_all(&feed).await.unwrap();
        stdin.shutdown().await.unwrap();
        stdin
    });
    let mut echoed = Vec::new();
    while let Some(ev) = timeout(LIMIT, events.next()).await.expect("hung").unwrap() {
        if let ExecEvent::Stdout(d) = ev {
            echoed.extend(d);
        }
    }
    let _ = pump.await.unwrap();
    assert!(echoed == data, "Daten verändert");
    assert!(
        s.rekey_count() >= 5,
        "nur {} Schlüsselwechsel",
        s.rekey_count()
    );
}

#[tokio::test]
async fn overlong_commands_are_rejected_locally() {
    let sshd = sshd_or_skip!();
    let s = session(&sshd).await;
    let long = "x".repeat(2 * 1024 * 1024);
    match s.exec_stream(&long).await {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
        other => panic!("{:?}", other.err()),
    }
    assert_eq!(s.exec("echo ok").await.unwrap().stdout, b"ok\n");
}
