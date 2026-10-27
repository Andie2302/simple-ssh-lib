use crate::error::{Error, Result};

/// Liest SSH-Datentypen aus einem Byte-Slice.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(Error::UnexpectedEof);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub fn get_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Strikt: nur 0 und 1 sind gültig.
    pub fn get_bool(&mut self) -> Result<bool> {
        match self.get_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Malformed("boolean not 0 or 1")),
        }
    }

    pub fn get_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn get_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn get_raw(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }

    pub fn get_string(&mut self) -> Result<&'a [u8]> {
        let len = self.get_u32()? as usize;
        self.take(len)
    }

    pub fn get_str(&mut self) -> Result<&'a str> {
        std::str::from_utf8(self.get_string()?).map_err(|_| Error::Malformed("invalid utf-8"))
    }

    /// Positiver `mpint`; liefert die Big-Endian-Ziffern ohne führende Nullen.
    /// Negative und nicht minimal kodierte Werte werden abgelehnt.
    pub fn get_mpint(&mut self) -> Result<&'a [u8]> {
        let raw = self.get_string()?;
        match raw {
            [] => Ok(raw),
            [first, ..] if first & 0x80 != 0 => Err(Error::Malformed("negative mpint")),
            [0, rest @ ..] if !rest.first().is_some_and(|b| b & 0x80 != 0) => {
                Err(Error::Malformed("mpint not minimally encoded"))
            }
            [0, rest @ ..] => Ok(rest),
            _ => Ok(raw),
        }
    }

    pub fn get_name_list(&mut self) -> Result<Vec<&'a str>> {
        let s = self.get_str()?;
        if s.is_empty() {
            return Ok(Vec::new());
        }
        Ok(s.split(',').collect())
    }

    /// Schlägt fehl, wenn noch ungelesene Bytes übrig sind.
    pub fn finish(self) -> Result<()> {
        match self.buf.len() {
            0 => Ok(()),
            n => Err(Error::TrailingData(n)),
        }
    }
}
