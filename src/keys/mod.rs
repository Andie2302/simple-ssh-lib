//! OpenSSH-Private-Keys (`-----BEGIN OPENSSH PRIVATE KEY-----`), nur ed25519.
//!
//! Unterstützt werden unverschlüsselte Keys und Keys mit Passphrase im
//! `ssh-keygen`-Standardformat (`aes256-ctr` + `bcrypt`).

mod base64;

use std::fmt;

use aes::Aes256;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::transport::HostKey;
use crate::wire::{Reader, Writer};

const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END: &str = "-----END OPENSSH PRIVATE KEY-----";
const MAGIC: &[u8] = b"openssh-key-v1\0";
const KEY_TYPE: &str = "ssh-ed25519";
/// Obergrenze für die bcrypt-Runden einer (nicht vertrauenswürdigen) Datei.
/// `ssh-keygen` nutzt standardmäßig 16.
const MAX_KDF_ROUNDS: u32 = 1024;

/// Ed25519-Private-Key. Der Seed wird beim Löschen überschrieben.
pub struct PrivateKey {
    signing: SigningKey,
    comment: String,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey({KEY_TYPE} {})", self.fingerprint())
    }
}

impl PrivateKey {
    /// Liest einen OpenSSH-Private-Key. `passphrase` ist nur für verschlüsselte Keys nötig.
    pub fn from_openssh(pem: &str, passphrase: Option<&[u8]>) -> Result<Self> {
        let der = decode_pem(pem)?;
        let mut r = Reader::new(&der);
        if r.get_raw(MAGIC.len())? != MAGIC {
            return Err(Error::Malformed("bad openssh-key magic"));
        }
        let cipher = r.get_str()?;
        let kdf = r.get_str()?;
        let kdf_options = r.get_string()?;
        if r.get_u32()? != 1 {
            return Err(Error::UnsupportedKey("more than one key in file"));
        }
        let public_blob = r.get_string()?;
        let encrypted = r.get_string()?;
        // AEAD-Cipher hängen einen Tag an; die lehnen wir unten ab, bevor das stört.
        if !matches!((cipher, kdf), ("none", "none") | ("aes256-ctr", "bcrypt")) {
            return Err(Error::UnsupportedKey("cipher or kdf"));
        }
        r.finish()?;

        let section = match (cipher, kdf) {
            ("none", "none") => Zeroizing::new(encrypted.to_vec()),
            ("aes256-ctr", "bcrypt") => decrypt(encrypted, kdf_options, passphrase)?,
            _ => return Err(Error::UnsupportedKey("cipher or kdf")),
        };
        let encrypted = cipher != "none";

        let mut r = Reader::new(&section);
        let (check1, check2) = (r.get_u32()?, r.get_u32()?);
        if check1 != check2 {
            return Err(if encrypted {
                Error::WrongPassphrase
            } else {
                Error::Malformed("check integers differ")
            });
        }
        if r.get_str()? != KEY_TYPE {
            return Err(Error::UnsupportedKey("only ssh-ed25519 is supported"));
        }
        let public: [u8; 32] = r
            .get_string()?
            .try_into()
            .map_err(|_| Error::Malformed("bad ed25519 public key"))?;
        let private = Zeroizing::new(r.get_string()?.to_vec());
        let comment = r.get_str()?.to_owned();
        // Padding: 1, 2, 3, ... bis zur Blockgröße.
        for (i, &b) in (1u8..).zip(r.get_raw(r.remaining())?) {
            if b != i {
                return Err(Error::Malformed("bad key padding"));
            }
        }

        if private.len() != 64 || private[32..] != public {
            return Err(Error::Malformed("bad ed25519 private key"));
        }
        let seed: [u8; 32] = private[..32].try_into().unwrap();
        let signing = SigningKey::from_bytes(&seed);
        if signing.verifying_key().as_bytes() != &public {
            return Err(Error::Malformed("private key does not match public key"));
        }
        let key = Self { signing, comment };
        if key.public_blob() != public_blob {
            return Err(Error::Malformed("public key blob mismatch"));
        }
        Ok(key)
    }

    /// Public Key im SSH-Wire-Format (`string "ssh-ed25519" | string key`).
    pub fn public_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_string(KEY_TYPE.as_bytes())
            .put_string(self.signing.verifying_key().as_bytes());
        w.into_vec()
    }

    /// `SHA256:...`, identisch zur Ausgabe von `ssh-keygen -lf`.
    pub fn fingerprint(&self) -> String {
        HostKey::from_blob(self.public_blob()).fingerprint()
    }

    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Roh-Ed25519-Signatur über `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

fn decode_pem(pem: &str) -> Result<Vec<u8>> {
    let pem = pem.trim();
    let body = pem
        .strip_prefix(BEGIN)
        .and_then(|s| s.strip_suffix(END))
        .ok_or(Error::Malformed("not an openssh private key"))?;
    base64::decode(body)
}

fn decrypt(
    encrypted: &[u8],
    kdf_options: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>> {
    let passphrase = match passphrase {
        Some(p) if !p.is_empty() => p,
        _ => return Err(Error::PassphraseRequired),
    };
    let mut opts = Reader::new(kdf_options);
    let salt = opts.get_string()?;
    let rounds = opts.get_u32()?;
    opts.finish()?;
    if rounds == 0 || rounds > MAX_KDF_ROUNDS || salt.is_empty() {
        return Err(Error::UnsupportedKey("kdf parameters"));
    }
    if encrypted.is_empty() || !encrypted.len().is_multiple_of(16) {
        return Err(Error::Malformed("bad encrypted section length"));
    }

    let mut material = Zeroizing::new([0u8; 48]);
    bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, &mut material[..])
        .map_err(|_| Error::UnsupportedKey("kdf parameters"))?;
    let key = Zeroizing::new(<[u8; 32]>::try_from(&material[..32]).unwrap());
    let iv: [u8; 16] = material[32..].try_into().unwrap();

    let mut section = Zeroizing::new(encrypted.to_vec());
    let mut cipher = Ctr128BE::<Aes256>::new(&(*key).into(), &iv.into());
    cipher.apply_keystream(&mut section);
    Ok(section)
}
