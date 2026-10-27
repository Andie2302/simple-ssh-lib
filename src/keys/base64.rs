//! Minimaler, strikter Base64-Dekoder (RFC 4648, Standard-Alphabet).

use crate::error::{Error, Result};

fn value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Dekodiert `input`; Leerraum wird ignoriert, Padding muss korrekt sein.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    let bad = || Error::Malformed("invalid base64");
    let chars: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let body_len = chars.iter().rposition(|&c| c != b'=').map_or(0, |i| i + 1);
    let (body, padding) = chars.split_at(body_len);
    if padding.len() > 2 || padding.iter().any(|&c| c != b'=') {
        return Err(bad());
    }
    if !padding.is_empty() && (body.len() + padding.len()) % 4 != 0 {
        return Err(bad());
    }
    if body.len() % 4 == 1 {
        return Err(bad());
    }

    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    for chunk in body.chunks(4) {
        let mut n = 0u32;
        for &c in chunk {
            n = n << 6 | value(c).ok_or_else(bad)?;
        }
        n <<= 6 * (4 - chunk.len() as u32);
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn rfc4648_vectors() {
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(decode("Zg==").unwrap(), b"f");
        assert_eq!(decode("Zm8=").unwrap(), b"fo");
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
        assert_eq!(decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(decode("Zm9v\nYmFy\n").unwrap(), b"foobar");
        assert_eq!(decode("Zg").unwrap(), b"f");
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode("Zm9v!mFy").is_err());
        assert!(decode("Z").is_err());
        assert!(decode("Zg=").is_err());
        assert!(decode("Zg===").is_err());
        assert!(decode("=Zg=").is_err());
    }
}
