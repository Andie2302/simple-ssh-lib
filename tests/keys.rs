//! OpenSSH-Private-Key-Parser gegen echte `ssh-keygen`-Dateien (tests/fixtures).

use ed25519_dalek::{Signature, VerifyingKey};
use simple_ssh_lib::Error;
use simple_ssh_lib::keys::PrivateKey;

const PLAIN: &str = include_str!("fixtures/ed25519_plain");
const ENCRYPTED: &str = include_str!("fixtures/ed25519_aes256ctr");
const GCM: &str = include_str!("fixtures/ed25519_aes256gcm");
const RSA: &str = include_str!("fixtures/rsa");
const PASSPHRASE: &[u8] = b"correct horse";

// Ausgabe von `ssh-keygen -lf` für die Fixtures.
const PLAIN_FINGERPRINT: &str = "SHA256:XZyzL7febSUq8g7pJpg+jFl7BdMASg3EJyi/UAdy17c";
const ENCRYPTED_FINGERPRINT: &str = "SHA256:FFmWMdWK9E5NVnhoxPEjo5MmvcrtbYiasbXV6MCOelA";

#[test]
fn reads_unencrypted_key() {
    let key = PrivateKey::from_openssh(PLAIN, None).unwrap();
    assert_eq!(key.fingerprint(), PLAIN_FINGERPRINT);
    assert_eq!(key.comment(), "test-plain");
}

#[test]
fn passphrase_is_ignored_for_unencrypted_key() {
    PrivateKey::from_openssh(PLAIN, Some(b"whatever")).unwrap();
}

#[test]
fn reads_encrypted_key_with_passphrase() {
    let key = PrivateKey::from_openssh(ENCRYPTED, Some(PASSPHRASE)).unwrap();
    assert_eq!(key.fingerprint(), ENCRYPTED_FINGERPRINT);
    assert_eq!(key.comment(), "test-encrypted");
}

#[test]
fn encrypted_key_needs_passphrase() {
    assert!(matches!(
        PrivateKey::from_openssh(ENCRYPTED, None),
        Err(Error::PassphraseRequired)
    ));
    assert!(matches!(
        PrivateKey::from_openssh(ENCRYPTED, Some(b"")),
        Err(Error::PassphraseRequired)
    ));
}

#[test]
fn wrong_passphrase_is_detected() {
    assert!(matches!(
        PrivateKey::from_openssh(ENCRYPTED, Some(b"wrong")),
        Err(Error::WrongPassphrase)
    ));
}

#[test]
fn unsupported_formats_are_reported() {
    assert!(matches!(
        PrivateKey::from_openssh(RSA, None),
        Err(Error::UnsupportedKey(_))
    ));
    assert!(matches!(
        PrivateKey::from_openssh(GCM, Some(b"x")),
        Err(Error::UnsupportedKey(_))
    ));
}

#[test]
fn malformed_input_is_rejected() {
    assert!(PrivateKey::from_openssh("", None).is_err());
    assert!(PrivateKey::from_openssh("hello", None).is_err());
    // Abgeschnitten: Anfang und Ende behalten, Mitte kürzen.
    let lines: Vec<&str> = PLAIN.lines().collect();
    let truncated = [lines[0], lines[1], lines[lines.len() - 1]].join("\n");
    assert!(PrivateKey::from_openssh(&truncated, None).is_err());
    // Ungültiges Base64-Zeichen.
    let corrupted = PLAIN.replacen("b3Bl", "b3B!", 1);
    assert!(matches!(
        PrivateKey::from_openssh(&corrupted, None),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn bit_flips_never_yield_a_key() {
    // Jedes verfälschte Base64-Zeichen im Körper muss zu einem Fehler führen
    // oder (nur bei Kommentar/Padding-neutralen Stellen) zum selben Key.
    let body_start = PLAIN.find('\n').unwrap() + 1;
    for i in (body_start..PLAIN.len() - 30).step_by(7) {
        let mut bytes = PLAIN.as_bytes().to_vec();
        if !bytes[i].is_ascii_alphanumeric() {
            continue;
        }
        bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        let s = String::from_utf8(bytes).unwrap();
        if let Ok(key) = PrivateKey::from_openssh(&s, None) {
            assert_eq!(key.fingerprint(), PLAIN_FINGERPRINT, "changed byte {i}");
        }
    }
}

#[test]
fn signature_verifies_with_public_key() {
    let key = PrivateKey::from_openssh(PLAIN, None).unwrap();
    // Public Key aus dem Blob: string "ssh-ed25519" | string key
    let blob = key.public_blob();
    let public: [u8; 32] = blob[blob.len() - 32..].try_into().unwrap();
    let verifying = VerifyingKey::from_bytes(&public).unwrap();
    let sig = Signature::from_bytes(&key.sign(b"message"));
    verifying.verify_strict(b"message", &sig).unwrap();
    assert!(verifying.verify_strict(b"other", &sig).is_err());
}

#[test]
fn debug_output_does_not_leak_secrets() {
    let key = PrivateKey::from_openssh(PLAIN, None).unwrap();
    let dbg = format!("{key:?}");
    assert!(dbg.contains(PLAIN_FINGERPRINT));
    assert!(!dbg.contains("Signing") && !dbg.contains("seed"));
}
