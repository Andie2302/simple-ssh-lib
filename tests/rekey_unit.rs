//! Bausteine des Schlüsselwechsels ohne Netzwerk: Prüfung von KEXINIT, Host-Key und
//! Signatur sowie die Regel, welche Nachrichten während des Wechsels erlaubt sind.

use ed25519_dalek::{Signer, SigningKey};
use simple_ssh_lib::Error;
use simple_ssh_lib::transport::kex::{self, DerivedKeys, EcdhClient, HashInput};
use simple_ssh_lib::transport::kexinit::{self, KEX_ALGORITHM, STRICT_KEX_SERVER};
use simple_ssh_lib::transport::rekey::{PendingKex, RekeyContext, is_kex_class};
use simple_ssh_lib::transport::version::CLIENT_BANNER;
use simple_ssh_lib::wire::{Reader, Writer};

const SERVER_BANNER: &str = "SSH-2.0-fake_1.0";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn host_key_blob(key: &SigningKey) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_string(b"ssh-ed25519")
        .put_string(key.verifying_key().as_bytes());
    w.into_vec()
}

fn context() -> RekeyContext {
    RekeyContext {
        server_banner: SERVER_BANNER.into(),
        session_id: [3u8; 32],
        host_key_blob: host_key_blob(&signing_key()),
    }
}

fn server_kexinit() -> Vec<u8> {
    kexinit::build(&[7u8; 16], &[KEX_ALGORITHM])
}

/// Antwort des Servers auf `init` samt den Schlüsseln, die er daraus ableitet.
fn server_reply(
    init: &[u8],
    ours: &[u8],
    key: &SigningKey,
    corrupt: bool,
) -> (Vec<u8>, DerivedKeys) {
    let mut r = Reader::new(init);
    assert_eq!(r.get_u8().unwrap(), kex::MSG_KEX_ECDH_INIT);
    let client_public = r.get_string().unwrap().to_vec();

    let ecdh = EcdhClient::from_seed([5u8; 32]);
    let server_public = ecdh.public_bytes();
    let secret = ecdh.diffie_hellman(&client_public).unwrap();
    let blob = host_key_blob(key);
    let h = kex::exchange_hash(
        &HashInput {
            client_banner: CLIENT_BANNER,
            server_banner: SERVER_BANNER,
            client_kexinit: ours,
            server_kexinit: &server_kexinit(),
            host_key_blob: &blob,
            client_public: &client_public,
            server_public: &server_public,
        },
        &secret,
    );
    let mut sig = key.sign(&h).to_bytes();
    if corrupt {
        sig[10] ^= 1;
    }
    let mut sig_blob = Writer::new();
    sig_blob.put_string(b"ssh-ed25519").put_string(&sig);
    let mut reply = Writer::new();
    reply
        .put_u8(kex::MSG_KEX_ECDH_REPLY)
        .put_string(&blob)
        .put_string(&server_public)
        .put_string(sig_blob.as_slice());
    (
        reply.into_vec(),
        kex::derive_keys(&secret, &h, &context().session_id),
    )
}

fn our_kexinit() -> Vec<u8> {
    kexinit::build_client_kexinit(false).unwrap()
}

#[test]
fn rekey_derives_the_same_keys_on_both_sides() {
    let ours = our_kexinit();
    let (pending, init) = PendingKex::begin(ours.clone(), server_kexinit()).unwrap();
    let (reply, server_keys) = server_reply(&init, &ours, &signing_key(), false);
    let client_keys = pending.finish(&context(), &reply).unwrap();
    assert_eq!(*client_keys.client_to_server, *server_keys.client_to_server);
    assert_eq!(*client_keys.server_to_client, *server_keys.server_to_client);
    assert_ne!(*client_keys.client_to_server, *client_keys.server_to_client);
}

#[test]
fn new_keys_differ_from_run_to_run() {
    let ours = our_kexinit();
    let (p1, i1) = PendingKex::begin(ours.clone(), server_kexinit()).unwrap();
    let (p2, i2) = PendingKex::begin(ours.clone(), server_kexinit()).unwrap();
    let (r1, _) = server_reply(&i1, &ours, &signing_key(), false);
    let (r2, _) = server_reply(&i2, &ours, &signing_key(), false);
    let k1 = p1.finish(&context(), &r1).unwrap();
    let k2 = p2.finish(&context(), &r2).unwrap();
    assert_ne!(*k1.client_to_server, *k2.client_to_server);
}

#[test]
fn a_different_host_key_during_rekey_is_rejected() {
    let ours = our_kexinit();
    let (pending, init) = PendingKex::begin(ours.clone(), server_kexinit()).unwrap();
    let other = SigningKey::from_bytes(&[42u8; 32]);
    let (reply, _) = server_reply(&init, &ours, &other, false);
    // Die Signatur wäre mit dem fremden Key gültig, der Key ist aber nicht der erste.
    let err = pending.finish(&context(), &reply).err().unwrap();
    assert!(matches!(err, Error::HostKeyRejected { .. }), "{err:?}");
}

#[test]
fn a_bad_signature_during_rekey_is_rejected() {
    let ours = our_kexinit();
    let (pending, init) = PendingKex::begin(ours.clone(), server_kexinit()).unwrap();
    let (reply, _) = server_reply(&init, &ours, &signing_key(), true);
    assert!(matches!(
        pending.finish(&context(), &reply).err().unwrap(),
        Error::BadSignature
    ));
}

#[test]
fn garbage_instead_of_ecdh_reply_is_rejected() {
    let ours = our_kexinit();
    let (pending, _) = PendingKex::begin(ours, server_kexinit()).unwrap();
    assert!(pending.finish(&context(), &[1, 2, 3]).is_err());
}

#[test]
fn strict_kex_marker_is_only_required_for_the_first_exchange() {
    let without = kexinit::build(&[0u8; 16], &[KEX_ALGORITHM]);
    let with = kexinit::build(&[0u8; 16], &[KEX_ALGORITHM, STRICT_KEX_SERVER]);
    assert!(kexinit::check_server_kexinit(&without, false).is_ok());
    assert!(kexinit::check_server_kexinit(&with, false).is_ok());
    assert!(matches!(
        kexinit::check_server_kexinit(&without, true),
        Err(Error::NoCommonAlgorithm("strict kex"))
    ));
    assert!(kexinit::check_server_kexinit(&with, true).is_ok());
}

#[test]
fn our_rekey_kexinit_carries_no_strict_marker() {
    let initial = kexinit::build_client_kexinit(true).unwrap();
    let later = kexinit::build_client_kexinit(false).unwrap();
    let marker = kexinit::STRICT_KEX_CLIENT.as_bytes();
    assert!(initial.windows(marker.len()).any(|w| w == marker));
    assert!(!later.windows(marker.len()).any(|w| w == marker));
}

#[test]
fn server_kexinit_without_our_algorithms_is_rejected_at_rekey() {
    let mut w = Writer::new();
    w.put_u8(kexinit::MSG_KEXINIT).put_raw(&[0u8; 16]);
    for _ in 0..10 {
        w.put_name_list(&["something-else"]);
    }
    w.put_bool(false).put_u32(0);
    assert!(matches!(
        PendingKex::begin(our_kexinit(), w.into_vec())
            .err()
            .unwrap(),
        Error::NoCommonAlgorithm(_)
    ));
}

#[test]
fn only_transport_level_messages_may_pass_during_a_key_exchange() {
    for allowed in [1u8, 2, 5, 20, 21, 30, 31, 49] {
        assert!(is_kex_class(allowed), "{allowed}");
    }
    // 50 = USERAUTH, 80 = GLOBAL_REQUEST, 90..100 = Channel-Nachrichten
    for held in [50u8, 80, 90, 94, 97, 98, 100] {
        assert!(!is_kex_class(held), "{held}");
    }
}
