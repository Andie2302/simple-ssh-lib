/// Baut eine SSH-Nachricht in einem `Vec<u8>` auf.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn put_bool(&mut self, v: bool) -> &mut Self {
        self.put_u8(v as u8)
    }

    pub fn put_u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn put_u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Rohe Bytes ohne Längenpräfix (z.B. der KEXINIT-Cookie).
    pub fn put_raw(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// `string`: uint32 Länge + Bytes.
    pub fn put_string(&mut self, v: &[u8]) -> &mut Self {
        let len = u32::try_from(v.len()).expect("string longer than u32::MAX");
        self.put_u32(len).put_raw(v)
    }

    /// `mpint` aus einer positiven Big-Endian-Zahl (führende Nullen sind erlaubt).
    pub fn put_mpint(&mut self, be: &[u8]) -> &mut Self {
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        let digits = &be[start..];
        match digits.first() {
            None => self.put_u32(0),
            Some(&b) if b & 0x80 != 0 => {
                let len = u32::try_from(digits.len() + 1).expect("mpint too long");
                self.put_u32(len).put_u8(0).put_raw(digits)
            }
            Some(_) => self.put_string(digits),
        }
    }

    /// `name-list`: kommagetrennte ASCII-Namen als string.
    pub fn put_name_list(&mut self, names: &[&str]) -> &mut Self {
        self.put_string(names.join(",").as_bytes())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}
