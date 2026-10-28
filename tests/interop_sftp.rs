//! SFTP gegen den echten `sftp-server` von OpenSSH. Überspringt sich ohne `sshd`.
//! Der Server läuft als derselbe Benutzer; geprüft wird auch direkt auf der Platte.

mod common;

use std::io::SeekFrom;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::time::Duration;

use common::{Options, Scratch, TestSshd};
use simple_ssh_lib::keys::PrivateKey;
use simple_ssh_lib::sftp::{OpenOptions, SftpStatus};
use simple_ssh_lib::transport::HostKeyCheck;
use simple_ssh_lib::{Config, Error, Session, Sftp};

fn config(sshd: &TestSshd) -> Config {
    let key = PrivateKey::from_openssh(&sshd.key_plain, None).unwrap();
    Config::new(
        &sshd.user,
        key,
        HostKeyCheck::Fingerprint(sshd.fingerprint.clone()),
    )
}

async fn start(sshd: &TestSshd) -> (Session, Sftp) {
    let session = Session::connect(sshd.addr(), config(sshd)).await.unwrap();
    let sftp = session.sftp().await.unwrap();
    (session, sftp)
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
    () => {
        sshd_or_skip!(Options::default())
    };
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(131) % 251) as u8)
        .collect()
}

#[tokio::test]
async fn small_file_roundtrip() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("sftp-small");
    let (_s, sftp) = start(&sshd).await;
    let path = scratch.path("hello.txt");
    sftp.write(&path, b"hello sftp").await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"hello sftp");
    assert_eq!(sftp.read(&path).await.unwrap(), b"hello sftp");
    // Überschreiben ersetzt den Inhalt, auch wenn er kürzer ist.
    sftp.write(&path, b"x").await.unwrap();
    assert_eq!(sftp.read(&path).await.unwrap(), b"x");
    // Leere Datei
    sftp.write(&path, b"").await.unwrap();
    assert_eq!(sftp.read(&path).await.unwrap(), b"");
}

#[tokio::test]
async fn ten_megabytes_roundtrip_byte_exact() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("sftp-large");
    let (_s, sftp) = start(&sshd).await;
    let data = pattern(10 * 1024 * 1024 + 123);
    let path = scratch.path("big.bin");
    sftp.write(&path, &data).await.unwrap();
    assert!(
        std::fs::read(&path).unwrap() == data,
        "file on disk differs"
    );
    let back = sftp.read(&path).await.unwrap();
    assert!(back == data, "downloaded data differs");
}

#[tokio::test]
async fn metadata_types_and_permissions() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("sftp-meta");
    let (_s, sftp) = start(&sshd).await;
    let file = scratch.path("f");
    let link = scratch.path("l");
    std::fs::write(&file, b"12345").unwrap();
    symlink(&file, &link).unwrap();

    let m = sftp.metadata(&file).await.unwrap();
    assert!(m.is_file() && !m.is_dir());
    assert_eq!(m.size, Some(5));
    assert!(m.mtime.is_some() && m.uid.is_some());

    assert!(
        sftp.metadata(&scratch.dir.to_string_lossy())
            .await
            .unwrap()
            .is_dir()
    );
    assert!(sftp.symlink_metadata(&link).await.unwrap().is_symlink());
    assert!(sftp.metadata(&link).await.unwrap().is_file());

    sftp.set_permissions(&file, 0o640).await.unwrap();
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        sftp.metadata(&file).await.unwrap().permissions.unwrap() & 0o777,
        0o640
    );
}

#[tokio::test]
async fn directory_operations() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("sftp-dirs");
    let (_s, sftp) = start(&sshd).await;
    let dir = scratch.path("d");
    sftp.create_dir(&dir, Some(0o750)).await.unwrap();
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o750
    );

    let a = format!("{dir}/a");
    let b = format!("{dir}/b");
    sftp.write(&a, b"data").await.unwrap();
    sftp.rename(&a, &b).await.unwrap();
    assert!(!std::path::Path::new(&a).exists());
    assert_eq!(sftp.read(&b).await.unwrap(), b"data");

    let canonical = sftp.canonicalize(&format!("{dir}/../d/./b")).await.unwrap();
    assert_eq!(
        canonical,
        std::fs::canonicalize(&b).unwrap().to_string_lossy()
    );
    assert!(sftp.canonicalize(".").await.unwrap().starts_with('/'));

    sftp.remove_file(&b).await.unwrap();
    sftp.remove_dir(&dir).await.unwrap();
    assert!(!std::path::Path::new(&dir).exists());
}

#[tokio::test]
async fn listing_a_large_directory_needs_several_rounds() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("sftp-list");
    let (_s, sftp) = start(&sshd).await;
    let mut expected: Vec<String> = (0..500).map(|i| format!("file-{i:04}.txt")).collect();
    for name in &expected {
        std::fs::write(scratch.path(name), name.as_bytes()).unwrap();
    }
    std::fs::create_dir(scratch.path("subdir")).unwrap();
    expected.push("subdir".into());

    let entries = sftp.read_dir(&scratch.dir.to_string_lossy()).await.unwrap();
    let mut names: Vec<_> = entries.iter().map(|e| e.name.clone()).collect();
    names.sort();
    expected.sort();
    assert_eq!(names, expected);
    assert!(
        entries
            .iter()
            .find(|e| e.name == "subdir")
            .unwrap()
            .metadata
            .is_dir()
    );
    assert_eq!(
        entries
            .iter()
            .find(|e| e.name == "file-0007.txt")
            .unwrap()
            .metadata
            .size,
        Some(13)
    );
    assert!(
        sftp.read_dir(&scratch.path("missing"))
            .await
            .unwrap_err()
            .is_not_found()
    );
}

#[tokio::test]
async fn server_errors_map_to_status_codes() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("sftp-errors");
    let (_s, sftp) = start(&sshd).await;

    let err = sftp.metadata(&scratch.path("missing")).await.unwrap_err();
    assert!(err.is_not_found(), "{err:?}");
    assert!(
        sftp.read(&scratch.path("missing"))
            .await
            .unwrap_err()
            .is_not_found()
    );

    let dir = scratch.path("full");
    sftp.create_dir(&dir, None).await.unwrap();
    sftp.write(&format!("{dir}/x"), b"x").await.unwrap();
    let err = sftp.remove_dir(&dir).await.unwrap_err();
    assert!(
        matches!(
            err,
            Error::Sftp {
                status: SftpStatus::Failure,
                ..
            }
        ),
        "{err:?}"
    );

    let existing = scratch.path("exists");
    sftp.write(&existing, b"1").await.unwrap();
    let err = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sftp, &existing)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(
            err,
            Error::Sftp {
                status: SftpStatus::Failure,
                ..
            }
        ),
        "{err:?}"
    );

    // OpenSSH überschreibt beim Umbenennen kein vorhandenes Ziel.
    let other = scratch.path("other");
    sftp.write(&other, b"2").await.unwrap();
    assert!(matches!(
        sftp.rename(&other, &existing).await.unwrap_err(),
        Error::Sftp { .. }
    ));
    // Das Original bleibt unberührt.
    assert_eq!(sftp.read(&existing).await.unwrap(), b"1");
}

#[tokio::test]
async fn file_api_cursor_append_and_truncate() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("sftp-file");
    let (_s, sftp) = start(&sshd).await;
    let path = scratch.path("f.txt");

    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(&sftp, &path)
        .await
        .unwrap();
    f.write_all(b"hello world").await.unwrap();
    assert_eq!(f.position(), 11);
    assert_eq!(f.seek(SeekFrom::Start(6)).await.unwrap(), 6);
    let mut buf = [0u8; 5];
    assert_eq!(f.read(&mut buf).await.unwrap(), 5);
    assert_eq!(&buf, b"world");
    assert_eq!(f.read(&mut buf).await.unwrap(), 0);
    assert_eq!(f.seek(SeekFrom::End(-5)).await.unwrap(), 6);
    assert_eq!(f.read_at(0, &mut buf).await.unwrap(), 5);
    assert_eq!(&buf, b"hello");
    f.write_all_at(0, b"J").await.unwrap();
    assert_eq!(f.metadata().await.unwrap().size, Some(11));
    f.close().await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"Jello world");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let mut a = OpenOptions::new()
        .append(true)
        .open(&sftp, &path)
        .await
        .unwrap();
    a.write_all(b"!").await.unwrap();
    a.close().await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"Jello world!");

    let f = OpenOptions::new()
        .write(true)
        .open(&sftp, &path)
        .await
        .unwrap();
    f.set_len(5).await.unwrap();
    assert_eq!(f.metadata().await.unwrap().size, Some(5));
    f.set_len(8).await.unwrap();
    f.close().await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"Jello\0\0\0");

    // Gelesen wird auch ohne vorheriges Seek ab Position 0.
    let mut r = sftp.open(&path).await.unwrap();
    assert_eq!(r.read_to_end(100).await.unwrap(), b"Jello\0\0\0");
    assert!(
        sftp.open(&scratch.path("nope"))
            .await
            .err()
            .unwrap()
            .is_not_found()
    );
}

#[tokio::test]
async fn many_parallel_operations_on_one_connection() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("sftp-parallel");
    let (_s, sftp) = start(&sshd).await;
    let tasks: Vec<_> = (0..20usize)
        .map(|i| {
            let sftp = sftp.clone();
            let path = scratch.path(&format!("p{i}"));
            tokio::spawn(async move {
                let data = pattern(100_000 + i * 997);
                sftp.write(&path, &data).await.unwrap();
                assert!(sftp.read(&path).await.unwrap() == data, "task {i}");
                sftp.metadata(&path).await.unwrap().size
            })
        })
        .collect();
    for (i, task) in tasks.into_iter().enumerate() {
        assert_eq!(task.await.unwrap(), Some((100_000 + i * 997) as u64));
    }
}

#[tokio::test]
async fn read_limit_comes_from_config() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("sftp-limit");
    let session = Session::connect(sshd.addr(), config(&sshd).max_output(100_000))
        .await
        .unwrap();
    let sftp = session.sftp().await.unwrap();
    let path = scratch.path("big");
    std::fs::write(&path, pattern(500_000)).unwrap();
    assert!(matches!(sftp.read(&path).await, Err(Error::OutputTooLarge)));
    // Die Verbindung bleibt benutzbar, Teilstücke lassen sich weiterhin lesen.
    let mut f = sftp.open(&path).await.unwrap();
    let mut buf = [0u8; 10];
    assert_eq!(f.read(&mut buf).await.unwrap(), 10);
}

#[tokio::test]
async fn sftp_outlives_the_session_handle_and_shares_it_with_exec() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("sftp-lifetime");
    let session = Session::connect(sshd.addr(), config(&sshd)).await.unwrap();
    let sftp = session.sftp().await.unwrap();
    let path = scratch.path("f");
    sftp.write(&path, b"abc").await.unwrap();

    let cat = format!("cat {path}");
    let (out, data) = tokio::join!(session.exec(&cat), sftp.read(&path));
    assert_eq!(out.unwrap().stdout, b"abc");
    assert_eq!(data.unwrap(), b"abc");

    drop(session);
    sftp.write(&path, b"still works").await.unwrap();
    assert_eq!(sftp.read(&path).await.unwrap(), b"still works");
}

#[tokio::test]
async fn missing_subsystem_is_reported_clearly() {
    let sshd = sshd_or_skip!(Options {
        sftp: false,
        ..Options::default()
    });
    let session = Session::connect(sshd.addr(), config(&sshd)).await.unwrap();
    match session.sftp().await {
        Err(Error::SftpUnavailable(msg)) => eprintln!("message: {msg}"),
        other => panic!("expected SftpUnavailable, got {:?}", other.err()),
    }
    // Die Session selbst ist weiter benutzbar.
    assert_eq!(session.exec("echo ok").await.unwrap().stdout, b"ok\n");
}

#[tokio::test]
async fn connection_loss_surfaces_as_error() {
    let sshd = sshd_or_skip!();
    let (session, sftp) = start(&sshd).await;
    // Beendet den sshd-Prozess dieser Verbindung abrupt.
    let _ = tokio::time::timeout(Duration::from_secs(10), session.exec("kill -9 $PPID")).await;
    let result = tokio::time::timeout(Duration::from_secs(10), sftp.metadata("/"))
        .await
        .expect("sftp hung");
    assert!(result.is_err());
}

#[tokio::test]
async fn streaming_copy_roundtrip_reports_progress() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("sftp-copy");
    let (_s, sftp) = start(&sshd).await;
    let data = pattern(5 * 1024 * 1024 + 123);
    let path = scratch.path("stream.bin");

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&sftp, &path)
        .await
        .unwrap();
    let mut reader = &data[..];
    let mut last = 0;
    let mut calls = 0;
    let n = file
        .copy_from(0, &mut reader, |t| {
            assert!(t > last);
            last = t;
            calls += 1;
        })
        .await
        .unwrap();
    file.close().await.unwrap();
    assert_eq!(n, data.len() as u64);
    assert_eq!(last, n);
    assert!(calls > 100);
    assert_eq!(std::fs::read(&path).unwrap(), data);

    let file = sftp.open(&path).await.unwrap();
    let mut out = Vec::new();
    let n = file.copy_to(0, &mut out, |_| {}).await.unwrap();
    assert_eq!(n, data.len() as u64);
    assert_eq!(out, data);

    // Ab einem Offset (Fortsetzen) und leere Datei.
    let mut tail = Vec::new();
    file.copy_to(1_000_000, &mut tail, |_| {}).await.unwrap();
    assert_eq!(tail, data[1_000_000..]);
    let empty = scratch.path("empty");
    sftp.write(&empty, b"").await.unwrap();
    let f = sftp.open(&empty).await.unwrap();
    let mut out = Vec::new();
    assert_eq!(f.copy_to(0, &mut out, |_| {}).await.unwrap(), 0);
    assert!(out.is_empty());
}

#[tokio::test]
async fn streaming_copy_errors_are_reported() {
    let sshd = sshd_or_skip!();
    let scratch = Scratch::new("sftp-copy-err");
    let (_s, sftp) = start(&sshd).await;
    // Schreiben in eine nur lesbar geöffnete Datei schlägt fehl.
    let path = scratch.path("ro.bin");
    sftp.write(&path, b"abc").await.unwrap();
    let file = sftp.open(&path).await.unwrap();
    let data = vec![1u8; 100_000];
    let mut reader = &data[..];
    let err = file.copy_from(0, &mut reader, |_| {}).await.unwrap_err();
    assert!(matches!(err, Error::Sftp { .. }), "{err:?}");
}
