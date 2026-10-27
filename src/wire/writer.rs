/// Größte Länge, die ein einzelnes Textfeld (Befehl, Pfad, Benutzername) haben darf.
pub const MAX_FIELD_LEN: usize = 1024 * 1024;

/// Prüft ein Feld aus Nutzereingaben gegen [`MAX_FIELD_LEN`].
pub fn check_field(value: &str, what: &'static str) -> crate::error::Result<()> {
    if value.len() > MAX_FIELD_LEN {
        return Err(crate::error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{what} is longer than {MAX_FIELD_LEN} bytes"),
        )));
    }
    Ok(())
}

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
    ///
    /// Felder über [`MAX_FIELD_LEN`] schickt die Bibliothek nie: Eingaben von außen
    /// werden vorher mit [`check_field`] begrenzt, Daten in kleinen Blöcken gesendet.
    pub fn put_string(&mut self, v: &[u8]) -> &mut Self {
        debug_assert!(v.len() <= MAX_FIELD_LEN, "string field too long");
        let len = u32::try_from(v.len()).unwrap_or(u32::MAX);
        self.put_u32(len).put_raw(v)
    }

    /// `mpint` aus einer positiven Big-Endian-Zahl (führende Nullen sind erlaubt).
    pub fn put_mpint(&mut self, be: &[u8]) -> &mut Self {
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        let digits = &be[start..];
        match digits.first() {
            None => self.put_u32(0),
            Some(&b) if b & 0x80 != 0 => {
                debug_assert!(digits.len() < MAX_FIELD_LEN, "mpint too long");
                let len = u32::try_from(digits.len() + 1).unwrap_or(u32::MAX);
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
