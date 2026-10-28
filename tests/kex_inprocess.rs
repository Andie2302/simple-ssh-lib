//! Client-Handshake gegen einen Mini-Server im selben Prozess (kein sshd nötig).
//! Der Server benutzt dieselben Bausteine wie der Client, prüft also vor allem
//! den Ablauf und die Fehlerpfade. Die Gegenprobe mit echtem OpenSSH steht in
//! `interop_sshd.rs`.

use ed25519_dalek::{Signer, SigningKey};
use simple_ssh_lib::Error;
use simple_ssh_lib::transport::cipher::{ChaChaPoly, TAG_LEN};
use simple_ssh_lib::transport::kex::{self, EcdhClient, HashInput};
use simple_ssh_lib::transport::kexinit::{self, KEX_ALGORITHM, STRICT_KEX_SERVER};
use simple_ssh_lib::transport::packet::{read_packet, write_packet};
use simple_ssh_lib::transport::version;
use simple_ssh_lib::transport::{
    HostKey, HostKeyCheck, MSG_NEWKEYS, MSG_SERVICE_ACCEPT, Transport,
};
use simple_ssh_lib::wire::{Reader, Writer};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const SERVER_BANNER: &str = "SSH-2.0-fake_1.0";

#[derive(Clone, Copy, Default)]
struct Opts {
    omit_strict: bool,
    corrupt_signature: bool,
    /// Länge eines IGNORE-Pakets, das der Server vor SERVICE_ACCEPT schickt (0 = keins).
    ignore_len: usize,
}

fn host_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn host_key_blob() -> Vec<u8> {
    let mut w = Writer::new();
    w.put_string(b"ssh-ed25519")
        .put_string(host_signing_key().verifying_key().as_bytes());
    w.into_vec()
}

fn host_fingerprint() -> String {
    HostKey::from_blob(host_key_blob()).fingerprint()
}

async fn read_sealed(s: &mut DuplexStream, c: &ChaChaPoly, seq: u32) -> Vec<u8> {
    let mut enc_len = [0u8; 4];
    s.read_exact(&mut enc_len).await.unwrap();
    let len = c.decrypt_len(seq, &enc_len) as usize;
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.unwrap();
    let mut tag = [0u8; TAG_LEN];
    s.read_exact(&mut tag).await.unwrap();
    c.open(seq, &enc_len, &body, &tag).unwrap()
}

async fn fake_server(mut s: DuplexStream, opts: Opts) -> Result<(), Error> {
    let client_banner = version::exchange(&mut s, SERVER_BANNER).await?;
    let client_kexinit = read_packet(&mut s).await?;

    let kex_list: &[&str] = if opts.omit_strict {
        &[KEX_ALGORITHM]
    } else {
        &[KEX_ALGORITHM, STRICT_KEX_SERVER]
    };
    let server_kexinit = kexinit::build(&[5u8; 16], kex_list);
    write_packet(&mut s, &server_kexinit).await?;

    let init = read_packet(&mut s).await?;
    let mut r = Reader::new(&init);
    assert_eq!(r.get_u8()?, kex::MSG_KEX_ECDH_INIT);
    let client_public = r.get_string()?.to_vec();

    let ecdh = EcdhClient::from_seed([7u8; 32]);
    let server_public = ecdh.public_bytes();
    let secret = ecdh.diffie_hellman(&client_public)?;
    let blob = host_key_blob();
    let h = kex::exchange_hash(
        &HashInput {
            client_banner: &client_banner,
            server_banner: SERVER_BANNER,
            client_kexinit: &client_kexinit,
            server_kexinit: &server_kexinit,
            host_key_blob: &blob,
            client_public: &client_public,
            server_public: &server_public,
        },
        &secret,
    );
    let mut sig = host_signing_key().sign(&h).to_bytes();
    if opts.corrupt_signature {
        sig[0] ^= 1;
    }
    let mut sig_blob = Writer::new();
    sig_blob.put_string(b"ssh-ed25519").put_string(&sig);
    let mut reply = Writer::new();
    reply
        .put_u8(kex::MSG_KEX_ECDH_REPLY)
        .put_string(&blob)
        .put_string(&server_public)
        .put_string(sig_blob.as_slice());
    write_packet(&mut s, reply.as_slice()).await?;

    write_packet(&mut s, &[MSG_NEWKEYS]).await?;
    assert_eq!(read_packet(&mut s).await?, [MSG_NEWKEYS]);

    // Ab hier verschlüsselt, Sequenznummern starten wegen strict KEX bei 0.
    let keys = kex::derive_keys(&secret, &h, &h);
    let recv = ChaChaPoly::new(&keys.client_to_server);
    let send = ChaChaPoly::new(&keys.server_to_client);
    let request = read_sealed(&mut s, &recv, 0).await;
    assert_eq!(request[0], simple_ssh_lib::transport::MSG_SERVICE_REQUEST);
    let mut accept = Writer::new();
    accept
        .put_u8(MSG_SERVICE_ACCEPT)
        .put_string(b"ssh-userauth");
    let mut seq = 0;
    if opts.ignore_len > 0 {
        // OpenSSH schickt solche Pakete als Tarnverkehr; sie sind größer als 35000 Bytes möglich.
        let mut ignore = vec![2u8];
        ignore.extend(std::iter::repeat_n(0u8, opts.ignore_len));
        s.write_all(&send.seal_with_limit(seq, &ignore, 1 << 20)?)
            .await?;
        seq += 1;
    }
    s.write_all(&send.seal(seq, accept.as_slice())?).await?;
    s.flush().await?;
    Ok(())
}

async fn run(opts: Opts, check: HostKeyCheck) -> Result<Transport<DuplexStream>, Error> {
    let (client_end, server_end) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(fake_server(server_end, opts));
    let result = Transport::connect(client_end, &check).await;
    if result.is_ok() {
        // Bei Erfolg muss auch der Server fehlerfrei durchlaufen.
        let mut t = result;
        t.as_mut().unwrap().request_service("ssh-userauth").await?;
        server.await.unwrap()?;
        return t;
    }
    server.abort();
    result
}

#[tokio::test]
async fn full_handshake_and_service_request() {
    let t = run(
        Opts::default(),
        HostKeyCheck::Fingerprint(host_fingerprint()),
    )
    .await
    .unwrap();
    assert!(t.is_encrypted());
    assert_eq!(t.server_banner(), SERVER_BANNER);
    assert_eq!(t.host_key_fingerprint(), host_fingerprint());
}

#[tokio::test]
async fn callback_check_receives_host_key() {
    let expected = host_key_blob();
    let check = HostKeyCheck::Callback(Box::new(move |k| k.blob() == expected));
    run(Opts::default(), check).await.unwrap();
}

#[tokio::test]
async fn wrong_fingerprint_is_rejected() {
    let err = run(
        Opts::default(),
        HostKeyCheck::Fingerprint("SHA256:nope".into()),
    )
    .await
    .err()
    .unwrap();
    assert!(
        matches!(err, Error::HostKeyRejected { ref fingerprint } if *fingerprint == host_fingerprint())
    );
}

#[tokio::test]
async fn bad_signature_is_rejected_before_host_key_check() {
    let opts = Opts {
        corrupt_signature: true,
        ..Opts::default()
    };
    let err = run(opts, HostKeyCheck::Fingerprint(host_fingerprint()))
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::BadSignature));
}

#[tokio::test]
async fn server_without_strict_kex_is_rejected() {
    let opts = Opts {
        omit_strict: true,
        ..Opts::default()
    };
    let err = run(opts, HostKeyCheck::Fingerprint(host_fingerprint()))
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::NoCommonAlgorithm("strict kex")));
}

#[tokio::test]
async fn large_ignore_packets_from_the_server_are_accepted() {
    // OpenSSH schickt IGNORE-Pakete weit über 35000 Bytes.
    let opts = Opts {
        ignore_len: 100_000,
        ..Opts::default()
    };
    run(opts, HostKeyCheck::Fingerprint(host_fingerprint()))
        .await
        .unwrap();
}

#[tokio::test]
async fn absurdly_large_packets_are_rejected() {
    let opts = Opts {
        ignore_len: 300_000,
        ..Opts::default()
    };
    let err = match run(opts, HostKeyCheck::Fingerprint(host_fingerprint())).await {
        Ok(_) => panic!("Paket hätte abgelehnt werden müssen"),
        Err(e) => e,
    };
    assert!(
        matches!(err, Error::InvalidPacket("packet too large")),
        "{err:?}"
    );
}
