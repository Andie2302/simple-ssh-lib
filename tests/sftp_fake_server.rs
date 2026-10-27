//! SFTP-Client gegen einen handgeschriebenen Server auf `tokio::io::duplex`.
//! Prüft Fehlerpfade und Protokollrandfälle, die ein echter Server nie auslöst.
//! Läuft immer, ohne sshd.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use simple_ssh_lib::sftp::SftpStatus;
use simple_ssh_lib::wire::{Reader, Writer};
use simple_ssh_lib::{Error, Sftp};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const FXP_INIT: u8 = 1;
const FXP_VERSION: u8 = 2;
const FXP_OPEN: u8 = 3;
const FXP_CLOSE: u8 = 4;
const FXP_READ: u8 = 5;
const FXP_WRITE: u8 = 6;
const FXP_FSTAT: u8 = 8;
const FXP_STAT: u8 = 17;
const FXP_STATUS: u8 = 101;
const FXP_HANDLE: u8 = 102;
const FXP_DATA: u8 = 103;
const FXP_ATTRS: u8 = 105;

type Files = Arc<Mutex<HashMap<String, Vec<u8>>>>;

async fn read_req(s: &mut DuplexStream) -> std::io::Result<(u8, Vec<u8>)> {
    let len = s.read_u32().await? as usize;
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await?;
    Ok((body[0], body[1..].to_vec()))
}

async fn send_body(s: &mut DuplexStream, body: &[u8]) {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    let _ = s.write_all(&out).await;
}

fn reply(kind: u8, id: u32, fill: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(kind).put_u32(id);
    fill(&mut w);
    w.into_vec()
}

fn status(id: u32, code: u32) -> Vec<u8> {
    reply(FXP_STATUS, id, |w| {
        w.put_u32(code).put_string(b"fake").put_string(b"");
    })
}

fn attrs(size: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u32(0x01 | 0x04).put_u64(size).put_u32(0o100644);
    w.into_vec()
}

async fn handshake(s: &mut DuplexStream, version: u32) {
    let (kind, _) = read_req(s).await.unwrap();
    assert_eq!(kind, FXP_INIT);
    let mut w = Writer::new();
    w.put_u8(FXP_VERSION).put_u32(version);
    send_body(s, w.as_slice()).await;
}

#[derive(Clone, Copy, Default)]
struct Behavior {
    short_reads: bool,
    empty_data: bool,
    oversize_data: bool,
    fail_write_after: Option<usize>,
}

/// Kleiner Dateiserver im Speicher: OPEN, CLOSE, FSTAT, STAT, READ, WRITE.
async fn mem_server(mut s: DuplexStream, files: Files, b: Behavior) {
    handshake(&mut s, 3).await;
    let mut writes = 0usize;
    let mut seed = 12345u32;
    while let Ok((kind, body)) = read_req(&mut s).await {
        let mut r = Reader::new(&body);
        let id = r.get_u32().unwrap();
        let out = match kind {
            FXP_OPEN => {
                let path = r.get_str().unwrap().to_owned();
                let flags = r.get_u32().unwrap();
                let mut files = files.lock().unwrap();
                if flags & 0x08 != 0 {
                    let file = files.entry(path.clone()).or_default();
                    if flags & 0x10 != 0 {
                        file.clear();
                    }
                }
                if files.contains_key(&path) {
                    reply(FXP_HANDLE, id, |w| {
                        w.put_string(path.as_bytes());
                    })
                } else {
                    status(id, 2)
                }
            }
            FXP_CLOSE => status(id, 0),
            FXP_FSTAT | FXP_STAT => {
                let key = String::from_utf8(r.get_string().unwrap().to_vec()).unwrap();
                match files.lock().unwrap().get(&key) {
                    Some(f) => reply(FXP_ATTRS, id, |w| {
                        w.put_raw(&attrs(f.len() as u64));
                    }),
                    None => status(id, 2),
                }
            }
            FXP_READ => {
                let key = String::from_utf8(r.get_string().unwrap().to_vec()).unwrap();
                let offset = r.get_u64().unwrap() as usize;
                let len = r.get_u32().unwrap() as usize;
                let files = files.lock().unwrap();
                let file = &files[&key];
                if offset >= file.len() {
                    status(id, 1)
                } else if b.empty_data {
                    reply(FXP_DATA, id, |w| {
                        w.put_string(b"");
                    })
                } else if b.oversize_data {
                    reply(FXP_DATA, id, |w| {
                        w.put_string(&vec![1u8; len + 1]);
                    })
                } else {
                    seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                    let cap = if b.short_reads {
                        1 + (seed >> 16) as usize % 1000
                    } else {
                        len
                    };
                    let n = len.min(cap).min(file.len() - offset);
                    reply(FXP_DATA, id, |w| {
                        w.put_string(&file[offset..offset + n]);
                    })
                }
            }
            FXP_WRITE => {
                let key = String::from_utf8(r.get_string().unwrap().to_vec()).unwrap();
                let offset = r.get_u64().unwrap() as usize;
                let data = r.get_string().unwrap();
                writes += 1;
                if b.fail_write_after.is_some_and(|k| writes > k) {
                    status(id, 4)
                } else {
                    let mut files = files.lock().unwrap();
                    let file = files.get_mut(&key).unwrap();
                    if file.len() < offset + data.len() {
                        file.resize(offset + data.len(), 0);
                    }
                    file[offset..offset + data.len()].copy_from_slice(data);
                    status(id, 0)
                }
            }
            _ => status(id, 8),
        };
        send_body(&mut s, &out).await;
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

async fn connect(
    files: &[(&str, Vec<u8>)],
    b: Behavior,
) -> (Sftp, Files, tokio::task::JoinHandle<()>) {
    let (client, server) = tokio::io::duplex(1 << 20);
    let files: Files = Arc::new(Mutex::new(
        files
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
    ));
    let task = tokio::spawn(mem_server(server, files.clone(), b));
    (Sftp::from_stream(client).await.unwrap(), files, task)
}

// ---------------------------------------------------------------- Handshake

#[tokio::test]
async fn wrong_protocol_version_is_unavailable() {
    let (client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move { handshake(&mut server, 2).await });
    match Sftp::from_stream(client).await {
        Err(Error::SftpUnavailable(msg)) => assert!(msg.contains("version 2"), "{msg}"),
        other => panic!("{:?}", other.err()),
    }
}

#[tokio::test]
async fn hangup_during_handshake_is_unavailable() {
    let (client, server) = tokio::io::duplex(4096);
    drop(server);
    assert!(matches!(
        Sftp::from_stream(client).await,
        Err(Error::SftpUnavailable(_))
    ));
}

#[tokio::test]
async fn reply_that_is_not_version_is_unavailable() {
    let (client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let _ = read_req(&mut server).await;
        send_body(&mut server, &status(0, 0)).await;
    });
    assert!(matches!(
        Sftp::from_stream(client).await,
        Err(Error::SftpUnavailable(_))
    ));
}

// ------------------------------------------------------------ feindliche Server

#[tokio::test]
async fn oversized_packet_is_a_protocol_violation_and_poisons_the_client() {
    let (client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        handshake(&mut server, 3).await;
        let _ = read_req(&mut server).await;
        let _ = server.write_all(&(2u32 << 20).to_be_bytes()).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let sftp = Sftp::from_stream(client).await.unwrap();
    assert!(matches!(
        sftp.metadata("/x").await,
        Err(Error::ProtocolViolation(_))
    ));
    assert!(matches!(
        sftp.metadata("/y").await,
        Err(Error::ProtocolViolation(_))
    ));
}

#[tokio::test]
async fn response_with_unknown_id_is_a_protocol_violation() {
    let (client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        handshake(&mut server, 3).await;
        let (_, body) = read_req(&mut server).await.unwrap();
        let id = Reader::new(&body).get_u32().unwrap();
        send_body(&mut server, &status(id + 1000, 0)).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let sftp = Sftp::from_stream(client).await.unwrap();
    assert!(matches!(
        sftp.remove_file("/x").await,
        Err(Error::ProtocolViolation(_))
    ));
}

#[tokio::test]
async fn truncated_response_then_hangup_is_connection_lost() {
    let (client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        handshake(&mut server, 3).await;
        let _ = read_req(&mut server).await;
        let _ = server.write_all(&[0, 0, 0, 100, FXP_STATUS, 0, 0]).await;
        drop(server);
    });
    let sftp = Sftp::from_stream(client).await.unwrap();
    assert!(matches!(
        sftp.remove_file("/x").await,
        Err(Error::ConnectionLost(_))
    ));
}

#[tokio::test]
async fn data_longer_than_requested_is_rejected() {
    let (sftp, _, _) = connect(
        &[("f", pattern(1000))],
        Behavior {
            oversize_data: true,
            ..Behavior::default()
        },
    )
    .await;
    assert!(matches!(
        sftp.read("f").await,
        Err(Error::ProtocolViolation(_))
    ));
}

#[tokio::test]
async fn empty_data_instead_of_eof_does_not_loop_forever() {
    let (sftp, _, _) = connect(
        &[("f", pattern(1000))],
        Behavior {
            empty_data: true,
            ..Behavior::default()
        },
    )
    .await;
    let result = tokio::time::timeout(Duration::from_secs(5), sftp.read("f"))
        .await
        .expect("hung");
    assert!(matches!(result, Err(Error::ProtocolViolation(_))));
}

// ------------------------------------------------------ Lesen und Schreiben

#[tokio::test]
async fn short_reads_still_produce_the_complete_file() {
    let data = pattern(300_000);
    let (sftp, _, _) = connect(
        &[("f", data.clone())],
        Behavior {
            short_reads: true,
            ..Behavior::default()
        },
    )
    .await;
    let read = tokio::time::timeout(Duration::from_secs(20), sftp.read("f"))
        .await
        .expect("hung")
        .unwrap();
    assert_eq!(read.len(), data.len());
    assert!(read == data, "content differs");
}

#[tokio::test]
async fn full_reads_roundtrip_various_sizes() {
    for size in [0usize, 1, 32767, 32768, 32769, 5 * 32768, 700_000] {
        let data = pattern(size);
        let (sftp, _, _) = connect(&[("f", data.clone())], Behavior::default()).await;
        let read = sftp.read("f").await.unwrap();
        assert!(read == data, "size {size}");
    }
}

#[tokio::test]
async fn read_limit_is_enforced() {
    let (sftp, _, _) = connect(&[("f", pattern(1_000_000))], Behavior::default()).await;
    let sftp = sftp.max_read(100_000);
    assert!(matches!(sftp.read("f").await, Err(Error::OutputTooLarge)));
    // genau am Limit ist erlaubt
    let (sftp, _, _) = connect(&[("g", pattern(65_536))], Behavior::default()).await;
    assert_eq!(sftp.max_read(65_536).read("g").await.unwrap().len(), 65_536);
}

#[tokio::test]
async fn write_stores_the_data_in_order() {
    let data = pattern(1_000_000);
    let (sftp, files, _) = connect(&[], Behavior::default()).await;
    sftp.write("new", &data).await.unwrap();
    assert!(files.lock().unwrap()["new"] == data);
}

#[tokio::test]
async fn write_failure_midway_is_reported_without_hanging() {
    let (sftp, _, _) = connect(
        &[],
        Behavior {
            fail_write_after: Some(3),
            ..Behavior::default()
        },
    )
    .await;
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        sftp.write("new", &pattern(1_000_000)),
    )
    .await
    .expect("hung");
    assert!(
        matches!(
            result,
            Err(Error::Sftp {
                status: SftpStatus::Failure,
                ..
            })
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn missing_file_maps_to_not_found() {
    let (sftp, _, _) = connect(&[], Behavior::default()).await;
    let err = sftp.read("nope").await.unwrap_err();
    assert!(err.is_not_found(), "{err:?}");
}

// ------------------------------------------------------- Pipelining / Abbruch

#[tokio::test]
async fn responses_may_arrive_in_any_order() {
    let (client, mut server) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        handshake(&mut server, 3).await;
        let mut batch = Vec::new();
        for _ in 0..8 {
            let (kind, body) = read_req(&mut server).await.unwrap();
            assert_eq!(kind, FXP_STAT);
            let mut r = Reader::new(&body);
            let id = r.get_u32().unwrap();
            let n: u64 = r
                .get_str()
                .unwrap()
                .trim_start_matches('a')
                .parse()
                .unwrap();
            batch.push((id, n));
        }
        for (id, n) in batch.into_iter().rev() {
            let a = attrs(n * 100);
            send_body(
                &mut server,
                &reply(FXP_ATTRS, id, |w| {
                    w.put_raw(&a);
                }),
            )
            .await;
        }
        let _ = read_req(&mut server).await; // offen halten
    });
    let sftp = Sftp::from_stream(client).await.unwrap();
    let tasks: Vec<_> = (0..8u64)
        .map(|i| {
            let s = sftp.clone();
            tokio::spawn(async move { (i, s.metadata(&format!("a{i}")).await.unwrap()) })
        })
        .collect();
    for task in tasks {
        let (i, meta) = task.await.unwrap();
        assert_eq!(meta.size, Some(i * 100), "request {i} got the wrong answer");
    }
}

#[tokio::test]
async fn cancelled_request_does_not_desync_the_stream() {
    let (client, mut server) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        handshake(&mut server, 3).await;
        while let Ok((_, body)) = read_req(&mut server).await {
            let mut r = Reader::new(&body);
            let id = r.get_u32().unwrap();
            if r.get_str().unwrap() == "slow" {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            let a = attrs(42);
            send_body(
                &mut server,
                &reply(FXP_ATTRS, id, |w| {
                    w.put_raw(&a);
                }),
            )
            .await;
        }
    });
    let sftp = Sftp::from_stream(client).await.unwrap();
    // Abbruch, bevor die Antwort da ist; die späte Antwort darf nichts durcheinanderbringen.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), sftp.metadata("slow"))
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(sftp.metadata("fast").await.unwrap().size, Some(42));
}

#[tokio::test]
async fn dropping_the_client_closes_the_stream() {
    let (sftp, _, server) = connect(&[], Behavior::default()).await;
    drop(sftp);
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server still connected")
        .unwrap();
}

#[tokio::test]
async fn dropped_file_sends_a_close() {
    let (client, mut server) = tokio::io::duplex(1 << 16);
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        handshake(&mut server, 3).await;
        let mut kinds = Vec::new();
        while let Ok((kind, body)) = read_req(&mut server).await {
            let id = Reader::new(&body).get_u32().unwrap();
            kinds.push(kind);
            let out = if kind == FXP_OPEN {
                reply(FXP_HANDLE, id, |w| {
                    w.put_string(b"h");
                })
            } else {
                status(id, 0)
            };
            send_body(&mut server, &out).await;
            if kind == FXP_CLOSE {
                break;
            }
        }
        let _ = tx.send(kinds);
    });
    let sftp = Sftp::from_stream(client).await.unwrap();
    drop(sftp.open("f").await.unwrap());
    let kinds = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kinds, [FXP_OPEN, FXP_CLOSE]);
}

#[tokio::test]
async fn file_cursor_read_write_and_seek() {
    let (sftp, files, _) = connect(&[("f", b"0123456789".to_vec())], Behavior::default()).await;
    let mut f = sftp.open("f").await.unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(f.read(&mut buf).await.unwrap(), 4);
    assert_eq!(&buf, b"0123");
    assert_eq!(f.seek(std::io::SeekFrom::Current(2)).await.unwrap(), 6);
    assert_eq!(f.read(&mut buf).await.unwrap(), 4);
    assert_eq!(&buf, b"6789");
    assert_eq!(f.read(&mut buf).await.unwrap(), 0);
    assert_eq!(f.seek(std::io::SeekFrom::End(-3)).await.unwrap(), 7);
    assert_eq!(f.read_to_end(100).await.unwrap(), b"789");
    assert!(f.seek(std::io::SeekFrom::Current(-100)).await.is_err());
    f.close().await.unwrap();

    let mut w = sftp.create("g").await.unwrap();
    w.write_all(b"hello ").await.unwrap();
    w.write_all(b"world").await.unwrap();
    assert_eq!(w.position(), 11);
    w.write_all_at(0, b"J").await.unwrap();
    w.close().await.unwrap();
    assert_eq!(files.lock().unwrap()["g"], b"Jello world");
}

#[tokio::test]
async fn invalid_open_options_are_rejected_locally() {
    use simple_ssh_lib::sftp::OpenOptions;
    let (sftp, _, _) = connect(&[], Behavior::default()).await;
    for opts in [
        OpenOptions::new(),
        OpenOptions::new().read(true).create(true).clone(),
        OpenOptions::new().append(true).truncate(true).clone(),
    ] {
        let err = opts.open(&sftp, "x").await.err().unwrap();
        assert!(
            matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidInput),
            "{err:?}"
        );
    }
}
