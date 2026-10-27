//! Robustheitstests ("Pseudo-Fuzzing") für alle Parser, die Daten aus dem Netz oder aus
//! Dateien lesen. Ausgehend von gültigen Beispielen werden zufällig Bytes verändert,
//! gekürzt, verlängert und Längenfelder vergiftet. Erwartung: nie Panik, nie Hänger.
//!
//! Das ersetzt kein coverage-gesteuertes Fuzzing (siehe `fuzz/`), läuft aber überall.
//! Die Zahl der Durchläufe pro Ziel steuert `FUZZ_ITERS` (Standard 20 000).

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use simple_ssh_lib::fuzz_api as fuzz;
use simple_ssh_lib::transport::cipher::ChaChaPoly;
use simple_ssh_lib::transport::kexinit::{self, KEX_ALGORITHM, STRICT_KEX_SERVER};
use simple_ssh_lib::transport::packet;
use simple_ssh_lib::wire::Writer;

/// Asynchrones Ziel: bekommt die Eingabe und liefert ein Future.
type AsyncTarget = fn(Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

const HOURGLASS: Duration = Duration::from_secs(300);

fn iterations() -> usize {
    std::env::var("FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

/// Kleiner, deterministischer Zufallsgenerator (xorshift64*).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    if rng.below(10) == 0 {
        let len = rng.below(300);
        return rng.bytes(len);
    }
    let mut v = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        let len = v.len();
        match rng.below(9) {
            0 if len > 0 => {
                let (i, bit) = (rng.below(len), rng.below(8));
                v[i] ^= 1 << bit;
            }
            1 if len > 0 => {
                let i = rng.below(len);
                v[i] = rng.next() as u8;
            }
            2 => v.truncate(rng.below(len + 1)),
            3 => {
                let n = rng.below(64);
                v.extend(rng.bytes(n));
            }
            4 if len >= 4 => {
                let i = rng.below(len - 3);
                let poison: [u8; 4] = match rng.below(4) {
                    0 => [0xFF; 4],
                    1 => [0x7F, 0xFF, 0xFF, 0xFF],
                    2 => [0x80, 0, 0, 0],
                    _ => [0; 4],
                };
                v[i..i + 4].copy_from_slice(&poison);
            }
            5 if len > 0 => {
                let (start, n) = (rng.below(len), 1 + rng.below(16));
                let end = (start + n).min(len);
                let chunk = v[start..end].to_vec();
                let at = rng.below(len + 1);
                v.splice(at..at, chunk);
            }
            6 if len > 0 => {
                let (start, n) = (rng.below(len), 1 + rng.below(16));
                let end = (start + n).min(len);
                v[start..end].fill(0);
            }
            7 if len > 1 => {
                let (a, b) = (rng.below(len), rng.below(len));
                v.swap(a, b);
            }
            8 => {
                let at = rng.below(len + 1);
                v.insert(at, rng.next() as u8);
            }
            _ => {}
        }
    }
    v
}

/// Führt `target` für alle Seeds mit `iters` Mutationen aus; hängt es, schlägt der Test fehl.
fn hammer(
    name: &'static str,
    seeds: Vec<Vec<u8>>,
    iters: usize,
    target: impl Fn(&[u8]) + Send + 'static,
) {
    assert!(!seeds.is_empty(), "{name}: no seeds");
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ name.len() as u64);
        for seed in &seeds {
            target(seed); // das Original selbst
            for _ in 0..iters {
                let input = mutate(&mut rng, seed);
                target(&input);
            }
        }
        let _ = done_tx.send(());
    });
    if done_rx.recv_timeout(HOURGLASS).is_err() {
        // Panik im Worker (Kanal geschlossen) oder Hänger (Zeitüberschreitung)
        match worker.join() {
            Err(_) => panic!("{name}: panicked"),
            Ok(()) => panic!("{name}: no result"),
        }
    }
    worker.join().unwrap_or_else(|_| panic!("{name}: panicked"));
}

/// Wie `hammer`, aber für asynchrone Ziele (weniger Durchläufe, da teurer).
fn hammer_async(name: &'static str, seeds: Vec<Vec<u8>>, iters: usize, target: AsyncTarget) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut rng = Rng(0xA5A5_5A5A_1234_5678 ^ name.len() as u64);
    let started = std::time::Instant::now();
    for seed in &seeds {
        runtime.block_on(target(seed.clone()));
        for _ in 0..iters {
            let input = mutate(&mut rng, seed);
            runtime.block_on(target(input));
        }
    }
    assert!(started.elapsed() < HOURGLASS, "{name}: too slow");
}

// ------------------------------------------------------------------ Seeds

fn wire_seed() -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(20)
        .put_bool(true)
        .put_u32(0xDEAD_BEEF)
        .put_u64(1 << 40)
        .put_string(b"hello")
        .put_mpint(&[0x80, 1, 2, 3])
        .put_name_list(&["a", "b", "c"])
        .put_string(b"");
    w.into_vec()
}

fn kexinit_seeds() -> Vec<Vec<u8>> {
    vec![
        kexinit::build(&[1u8; 16], &[KEX_ALGORITHM, STRICT_KEX_SERVER]),
        kexinit::build(&[2u8; 16], &[KEX_ALGORITHM]),
    ]
}

fn ecdh_reply_seed() -> Vec<u8> {
    let mut blob = Writer::new();
    blob.put_string(b"ssh-ed25519").put_string(&[7u8; 32]);
    let mut sig = Writer::new();
    sig.put_string(b"ssh-ed25519").put_string(&[9u8; 64]);
    let mut w = Writer::new();
    w.put_u8(31)
        .put_string(blob.as_slice())
        .put_string(&[5u8; 32])
        .put_string(sig.as_slice());
    w.into_vec()
}

fn sftp_seeds() -> Vec<Vec<u8>> {
    let status = {
        let mut w = Writer::new();
        w.put_u8(101)
            .put_u32(1)
            .put_u32(2)
            .put_string(b"no such file")
            .put_string(b"en");
        w.into_vec()
    };
    let handle = {
        let mut w = Writer::new();
        w.put_u8(102).put_u32(2).put_string(b"handle-1");
        w.into_vec()
    };
    let data = {
        let mut w = Writer::new();
        w.put_u8(103).put_u32(3).put_string(&[1, 2, 3, 4, 5]);
        w.into_vec()
    };
    let name = {
        let mut w = Writer::new();
        w.put_u8(104).put_u32(4).put_u32(2);
        for n in ["a.txt", "dir"] {
            w.put_string(n.as_bytes())
                .put_string(b"-rw-r--r-- 1 u g 5 Jan 1 a");
            w.put_u32(0x0F)
                .put_u64(5)
                .put_u32(1000)
                .put_u32(1000)
                .put_u32(0o100644)
                .put_u32(1)
                .put_u32(2);
        }
        w.into_vec()
    };
    let attrs = {
        let mut w = Writer::new();
        w.put_u8(105)
            .put_u32(5)
            .put_u32(0x8000_000F)
            .put_u64(9)
            .put_u32(1)
            .put_u32(2);
        w.put_u32(0o40755)
            .put_u32(3)
            .put_u32(4)
            .put_u32(1)
            .put_string(b"k")
            .put_string(b"v");
        w.into_vec()
    };
    vec![status, handle, data, name, attrs]
}

fn dispatch_seeds() -> Vec<Vec<u8>> {
    let m = |kind: u8, fill: &dyn Fn(&mut Writer)| {
        let mut w = Writer::new();
        w.put_u8(kind);
        fill(&mut w);
        w.into_vec()
    };
    vec![
        m(80, &|w| {
            w.put_string(b"hostkeys-00@openssh.com").put_bool(true);
        }),
        m(90, &|w| {
            w.put_string(b"forwarded-tcpip")
                .put_u32(3)
                .put_u32(100)
                .put_u32(100);
        }),
        m(91, &|w| {
            w.put_u32(0).put_u32(5).put_u32(2000).put_u32(500);
        }),
        m(92, &|w| {
            w.put_u32(0).put_u32(2).put_string(b"nope").put_string(b"");
        }),
        m(93, &|w| {
            w.put_u32(0).put_u32(100);
        }),
        m(94, &|w| {
            w.put_u32(0).put_string(b"payload");
        }),
        m(95, &|w| {
            w.put_u32(0).put_u32(1).put_string(b"stderr");
        }),
        m(96, &|w| {
            w.put_u32(0);
        }),
        m(97, &|w| {
            w.put_u32(0);
        }),
        m(98, &|w| {
            w.put_u32(0)
                .put_string(b"exit-status")
                .put_bool(false)
                .put_u32(1);
        }),
        m(98, &|w| {
            w.put_u32(0)
                .put_string(b"exit-signal")
                .put_bool(false)
                .put_string(b"KILL");
        }),
        m(99, &|w| {
            w.put_u32(0);
        }),
        m(100, &|w| {
            w.put_u32(0);
        }),
    ]
}

fn key_seeds() -> Vec<Vec<u8>> {
    vec![
        include_bytes!("fixtures/ed25519_plain").to_vec(),
        include_bytes!("fixtures/ed25519_aes256gcm").to_vec(),
        include_bytes!("fixtures/rsa").to_vec(),
    ]
}

// ------------------------------------------------------------------ Tests

#[test]
fn wire_reader_survives_mutations() {
    hammer(
        "wire_reader",
        vec![wire_seed(), vec![], vec![0xFF; 40]],
        iterations(),
        fuzz::wire_reader,
    );
}

#[test]
fn packet_bodies_survive_mutations() {
    let mut seeds = Vec::new();
    for len in [0usize, 1, 5, 17, 100] {
        let encoded = packet::encode(&vec![7u8; len]).unwrap();
        seeds.push(encoded[4..].to_vec());
    }
    hammer("packet_body", seeds, iterations(), fuzz::packet_body);
}

#[test]
fn kexinit_parser_survives_mutations() {
    hammer("kexinit", kexinit_seeds(), iterations(), fuzz::kexinit);
}

#[test]
fn ecdh_reply_and_signature_parsers_survive_mutations() {
    hammer(
        "ecdh_reply",
        vec![ecdh_reply_seed()],
        iterations(),
        fuzz::ecdh_reply,
    );
    let mut blob_and_sig = vec![30u8];
    blob_and_sig.extend_from_slice(&ecdh_reply_seed());
    hammer(
        "host_signature",
        vec![blob_and_sig],
        iterations(),
        fuzz::host_signature,
    );
}

#[test]
fn encrypted_packets_survive_mutations() {
    let cipher = ChaChaPoly::new(&[0x42; 64]);
    let seeds = vec![
        cipher.seal(0, b"hello").unwrap(),
        cipher.seal(0, &[0u8; 300]).unwrap(),
    ];
    hammer("cipher_open", seeds, iterations(), fuzz::cipher_open);
}

#[test]
fn sftp_responses_survive_mutations() {
    hammer(
        "sftp_response",
        sftp_seeds(),
        iterations(),
        fuzz::sftp_response,
    );
}

#[test]
fn server_channel_messages_survive_mutations() {
    hammer(
        "mux_dispatch",
        dispatch_seeds(),
        iterations(),
        fuzz::mux_dispatch,
    );
}

#[test]
fn key_files_survive_mutations() {
    // bcrypt macht verschlüsselte Schlüssel teuer; hier reichen weniger Durchläufe.
    hammer(
        "private_key",
        key_seeds(),
        iterations() / 4,
        fuzz::private_key,
    );
    let text_seeds = vec![
        b"Zm9vYmFy".to_vec(),
        b"Zg==\nZm8=\n".to_vec(),
        include_bytes!("fixtures/ed25519_plain").to_vec(),
    ];
    hammer("base64", text_seeds, iterations(), fuzz::base64_decode);
}

#[test]
fn banner_exchange_survives_mutations() {
    let seeds = vec![
        b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(),
        b"Welcome\r\nHello\r\nSSH-2.0-Server\r\n".to_vec(),
        b"SSH-1.99-Old\n".to_vec(),
    ];
    hammer_async("banner", seeds, iterations() / 10, |d| {
        Box::pin(async move { fuzz::banner(&d).await })
    });
}

#[test]
fn sftp_server_streams_survive_mutations() {
    let mut seeds = sftp_seeds();
    // Rahmen mit Längenfeld, wie sie über den Draht kommen.
    for seed in &mut seeds {
        let mut framed = (seed.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(seed);
        *seed = framed;
    }
    hammer_async("sftp_stream", seeds, iterations() / 100, |d| {
        Box::pin(async move { fuzz::sftp_stream(&d).await })
    });
}
