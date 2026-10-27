//! chacha20-poly1305@openssh.com: Roundtrip und Manipulationserkennung.
//! Die Kompatibilität mit OpenSSH selbst prüft `interop_sshd.rs`.

use simple_ssh_lib::Error;
use simple_ssh_lib::transport::cipher::{ChaChaPoly, KEY_LEN, TAG_LEN};

fn key() -> [u8; KEY_LEN] {
    core::array::from_fn(|i| i as u8)
}

/// Zerlegt ein Paket in (enc_len, enc_body, tag).
fn split(p: &[u8]) -> ([u8; 4], Vec<u8>, [u8; TAG_LEN]) {
    let (len, rest) = p.split_at(4);
    let (body, tag) = rest.split_at(rest.len() - TAG_LEN);
    (
        len.try_into().unwrap(),
        body.to_vec(),
        tag.try_into().unwrap(),
    )
}

#[test]
fn roundtrip_for_many_lengths() {
    let c = ChaChaPoly::new(&key());
    for n in 0..100 {
        let payload: Vec<u8> = (0..n as u8).collect();
        let wire = c.seal(7, &payload).unwrap();
        let (enc_len, body, tag) = split(&wire);
        let len = c.decrypt_len(7, &enc_len) as usize;
        assert_eq!(len, body.len());
        assert_eq!(len % 8, 0);
        assert_eq!(c.open(7, &enc_len, &body, &tag).unwrap(), payload);
    }
}

#[test]
fn ciphertext_hides_payload() {
    let c = ChaChaPoly::new(&key());
    let payload = [0x41u8; 32];
    let wire = c.seal(0, &payload).unwrap();
    assert!(!wire.windows(8).any(|w| w == [0x41; 8]));
}

#[test]
fn tampering_is_detected() {
    let c = ChaChaPoly::new(&key());
    let wire = c.seal(3, b"secret message").unwrap();
    let (enc_len, body, tag) = split(&wire);

    let mut bad_body = body.clone();
    bad_body[2] ^= 1;
    assert!(matches!(
        c.open(3, &enc_len, &bad_body, &tag),
        Err(Error::MacFailure)
    ));

    let mut bad_len = enc_len;
    bad_len[0] ^= 1;
    assert!(matches!(
        c.open(3, &bad_len, &body, &tag),
        Err(Error::MacFailure)
    ));

    let mut bad_tag = tag;
    bad_tag[15] ^= 1;
    assert!(matches!(
        c.open(3, &enc_len, &body, &bad_tag),
        Err(Error::MacFailure)
    ));
}

#[test]
fn wrong_sequence_number_fails() {
    let c = ChaChaPoly::new(&key());
    let wire = c.seal(1, b"x").unwrap();
    let (enc_len, body, tag) = split(&wire);
    assert!(matches!(
        c.open(2, &enc_len, &body, &tag),
        Err(Error::MacFailure)
    ));
}
