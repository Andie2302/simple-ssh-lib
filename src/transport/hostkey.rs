//! Host-Key-Darstellung und Prüfrichtlinie. Es gibt bewusst keinen Default.

use sha2::{Digest, Sha256};

/// Öffentlicher Host-Key des Servers im SSH-Wire-Format (`ssh-ed25519`).
#[derive(Debug, Clone)]
pub struct HostKey {
    blob: Vec<u8>,
}

impl HostKey {
    /// Aus dem Wire-Format (`string "ssh-ed25519" | string key`).
    pub fn from_blob(blob: Vec<u8>) -> Self {
        Self { blob }
    }

    /// Der Key im Wire-Format.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// OpenSSH-Fingerprint: `SHA256:` + Base64 (ohne Padding) des SHA-256 über den Blob.
    pub fn fingerprint(&self) -> String {
        format!("SHA256:{}", base64_nopad(&Sha256::digest(&self.blob)))
    }
}

/// Wie der Server-Host-Key geprüft wird.
pub enum HostKeyCheck {
    /// Erwarteter Fingerprint im Format `SHA256:...`.
    Fingerprint(String),
    /// Eigene Entscheidung, z.B. Abfrage in einer known_hosts-Datei.
    Callback(Box<dyn Fn(&HostKey) -> bool + Send + Sync>),
}

impl std::fmt::Debug for HostKeyCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fingerprint(fp) => f.debug_tuple("Fingerprint").field(fp).finish(),
            Self::Callback(_) => f.write_str("Callback(..)"),
        }
    }
}

impl HostKeyCheck {
    /// `true`, wenn die Richtlinie diesen Host-Key zulässt.
    pub fn accepts(&self, key: &HostKey) -> bool {
        match self {
            Self::Fingerprint(expected) => *expected == key.fingerprint(),
            Self::Callback(f) => f(key),
        }
    }
}

fn base64_nopad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64_nopad;

    #[test]
    fn base64_vectors() {
        assert_eq!(base64_nopad(b""), "");
        assert_eq!(base64_nopad(b"f"), "Zg");
        assert_eq!(base64_nopad(b"fo"), "Zm8");
        assert_eq!(base64_nopad(b"foo"), "Zm9v");
        assert_eq!(base64_nopad(b"foob"), "Zm9vYg");
        assert_eq!(base64_nopad(b"fooba"), "Zm9vYmE");
        assert_eq!(base64_nopad(b"foobar"), "Zm9vYmFy");
    }
}
