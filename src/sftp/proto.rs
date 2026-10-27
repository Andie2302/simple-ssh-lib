//! SFTP Version 3 (draft-ietf-secsh-filexfer-02): Paket- und Attributformat.

use crate::error::{Error, Result};
use crate::wire::{Reader, Writer};

pub const VERSION: u32 = 3;
/// Größtes Paket, das wir von einem Server annehmen (OpenSSH sendet höchstens ~256 KiB).
pub const MAX_PACKET: usize = 1024 * 1024;
/// Größte Handle-Länge laut Protokoll.
pub const MAX_HANDLE: usize = 256;

pub const FXP_INIT: u8 = 1;
pub const FXP_VERSION: u8 = 2;
pub const FXP_OPEN: u8 = 3;
pub const FXP_CLOSE: u8 = 4;
pub const FXP_READ: u8 = 5;
pub const FXP_WRITE: u8 = 6;
pub const FXP_LSTAT: u8 = 7;
pub const FXP_FSTAT: u8 = 8;
pub const FXP_SETSTAT: u8 = 9;
pub const FXP_FSETSTAT: u8 = 10;
pub const FXP_OPENDIR: u8 = 11;
pub const FXP_READDIR: u8 = 12;
pub const FXP_REMOVE: u8 = 13;
pub const FXP_MKDIR: u8 = 14;
pub const FXP_RMDIR: u8 = 15;
pub const FXP_REALPATH: u8 = 16;
pub const FXP_STAT: u8 = 17;
pub const FXP_RENAME: u8 = 18;
pub const FXP_STATUS: u8 = 101;
pub const FXP_HANDLE: u8 = 102;
pub const FXP_DATA: u8 = 103;
pub const FXP_NAME: u8 = 104;
pub const FXP_ATTRS: u8 = 105;

pub const PFLAG_READ: u32 = 0x01;
pub const PFLAG_WRITE: u32 = 0x02;
pub const PFLAG_APPEND: u32 = 0x04;
pub const PFLAG_CREAT: u32 = 0x08;
pub const PFLAG_TRUNC: u32 = 0x10;
pub const PFLAG_EXCL: u32 = 0x20;

const ATTR_SIZE: u32 = 0x01;
const ATTR_UIDGID: u32 = 0x02;
const ATTR_PERMISSIONS: u32 = 0x04;
const ATTR_ACMODTIME: u32 = 0x08;
const ATTR_EXTENDED: u32 = 0x8000_0000;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// Statuscode einer `SSH_FXP_STATUS`-Antwort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SftpStatus {
    /// Erfolg.
    Ok,
    /// Dateiende oder Ende der Verzeichnisliste.
    Eof,
    /// Datei oder Verzeichnis existiert nicht.
    NoSuchFile,
    /// Keine Berechtigung.
    PermissionDenied,
    /// Allgemeiner Fehler (z.B. Verzeichnis nicht leer oder Ziel existiert schon).
    Failure,
    /// Der Server hat die Anfrage nicht verstanden.
    BadMessage,
    /// Keine Verbindung zum Dateisystem des Servers.
    NoConnection,
    /// Verbindung des Servers zu seinem Dateisystem verloren.
    ConnectionLost,
    /// Operation wird vom Server nicht unterstützt.
    OpUnsupported,
    /// Anderer Statuscode.
    Other(u32),
}

impl From<u32> for SftpStatus {
    fn from(code: u32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::Eof,
            2 => Self::NoSuchFile,
            3 => Self::PermissionDenied,
            4 => Self::Failure,
            5 => Self::BadMessage,
            6 => Self::NoConnection,
            7 => Self::ConnectionLost,
            8 => Self::OpUnsupported,
            other => Self::Other(other),
        }
    }
}

/// Datei-Attribute. Felder, die der Server nicht meldet, sind `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    /// Größe in Bytes.
    pub size: Option<u64>,
    /// Benutzer-ID des Besitzers.
    pub uid: Option<u32>,
    /// Gruppen-ID des Besitzers.
    pub gid: Option<u32>,
    /// Unix-Modus inkl. Dateityp-Bits.
    pub permissions: Option<u32>,
    /// Sekunden seit 1970.
    pub atime: Option<u32>,
    /// Zeit der letzten Änderung (Sekunden seit 1970).
    pub mtime: Option<u32>,
}

impl Metadata {
    fn file_type_bits(&self) -> Option<u32> {
        self.permissions.map(|p| p & S_IFMT)
    }

    /// `true` für Verzeichnisse (laut Modus-Bits).
    pub fn is_dir(&self) -> bool {
        self.file_type_bits() == Some(S_IFDIR)
    }

    /// `true` für normale Dateien.
    pub fn is_file(&self) -> bool {
        self.file_type_bits() == Some(S_IFREG)
    }

    /// `true` für symbolische Links (nur bei `symlink_metadata` sichtbar).
    pub fn is_symlink(&self) -> bool {
        self.file_type_bits() == Some(S_IFLNK)
    }

    pub(crate) fn encode(&self, w: &mut Writer) {
        let mut flags = 0;
        if self.size.is_some() {
            flags |= ATTR_SIZE;
        }
        if self.uid.is_some() && self.gid.is_some() {
            flags |= ATTR_UIDGID;
        }
        if self.permissions.is_some() {
            flags |= ATTR_PERMISSIONS;
        }
        if self.atime.is_some() && self.mtime.is_some() {
            flags |= ATTR_ACMODTIME;
        }
        w.put_u32(flags);
        if let Some(size) = self.size {
            w.put_u64(size);
        }
        if let (Some(uid), Some(gid)) = (self.uid, self.gid) {
            w.put_u32(uid).put_u32(gid);
        }
        if let Some(p) = self.permissions {
            w.put_u32(p);
        }
        if let (Some(a), Some(m)) = (self.atime, self.mtime) {
            w.put_u32(a).put_u32(m);
        }
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let flags = r.get_u32()?;
        if flags & !(ATTR_SIZE | ATTR_UIDGID | ATTR_PERMISSIONS | ATTR_ACMODTIME | ATTR_EXTENDED)
            != 0
        {
            return Err(Error::Malformed("unknown sftp attribute flags"));
        }
        let mut m = Metadata::default();
        if flags & ATTR_SIZE != 0 {
            m.size = Some(r.get_u64()?);
        }
        if flags & ATTR_UIDGID != 0 {
            m.uid = Some(r.get_u32()?);
            m.gid = Some(r.get_u32()?);
        }
        if flags & ATTR_PERMISSIONS != 0 {
            m.permissions = Some(r.get_u32()?);
        }
        if flags & ATTR_ACMODTIME != 0 {
            m.atime = Some(r.get_u32()?);
            m.mtime = Some(r.get_u32()?);
        }
        if flags & ATTR_EXTENDED != 0 {
            let count = r.get_u32()? as usize;
            // Jedes Paar braucht mindestens 8 Bytes; schützt vor riesigen Schleifen.
            if count > r.remaining() / 8 {
                return Err(Error::Malformed("too many sftp attribute extensions"));
            }
            for _ in 0..count {
                r.get_string()?;
                r.get_string()?;
            }
        }
        Ok(m)
    }
}

/// Eintrag eines Verzeichnisses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Dateiname (nicht-UTF-8-Bytes werden ersetzt).
    pub name: String,
    /// Attribute des Eintrags.
    pub metadata: Metadata,
}

/// Geparste Antwort des Servers.
#[derive(Debug)]
pub(crate) enum Response {
    Status { status: SftpStatus, message: String },
    Handle(Vec<u8>),
    Data(Vec<u8>),
    Name(Vec<DirEntry>),
    Attrs(Metadata),
}

/// Zerlegt ein Antwortpaket (ohne Längenfeld) in Anfrage-ID und Inhalt.
pub(crate) fn parse_response(packet: &[u8]) -> Result<(u32, Response)> {
    let mut r = Reader::new(packet);
    let kind = r.get_u8()?;
    let id = r.get_u32()?;
    let response = match kind {
        FXP_STATUS => {
            let status = SftpStatus::from(r.get_u32()?);
            let message = String::from_utf8_lossy(r.get_string()?).into_owned();
            // Die Sprachkennung fehlt bei manchen Servern.
            if r.remaining() > 0 {
                r.get_string()?;
            }
            Response::Status { status, message }
        }
        FXP_HANDLE => {
            let handle = r.get_string()?;
            if handle.len() > MAX_HANDLE {
                return Err(Error::Malformed("sftp handle too long"));
            }
            Response::Handle(handle.to_vec())
        }
        FXP_DATA => Response::Data(r.get_string()?.to_vec()),
        FXP_NAME => {
            let count = r.get_u32()? as usize;
            // Eintrag = 2 Strings (je 4 Bytes Länge) + 4 Bytes Attribut-Flags.
            if count > r.remaining() / 12 {
                return Err(Error::Malformed("too many sftp name entries"));
            }
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let name = String::from_utf8_lossy(r.get_string()?).into_owned();
                r.get_string()?; // longname (nur Anzeige)
                entries.push(DirEntry {
                    name,
                    metadata: Metadata::decode(&mut r)?,
                });
            }
            Response::Name(entries)
        }
        FXP_ATTRS => Response::Attrs(Metadata::decode(&mut r)?),
        _ => return Err(Error::ProtocolViolation("unexpected sftp response type")),
    };
    r.finish()?;
    Ok((id, response))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_packet(id: u32, code: u32, msg: &str, with_lang: bool) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_u8(FXP_STATUS)
            .put_u32(id)
            .put_u32(code)
            .put_string(msg.as_bytes());
        if with_lang {
            w.put_string(b"en");
        }
        w.into_vec()
    }

    #[test]
    fn metadata_roundtrip() {
        let m = Metadata {
            size: Some(1 << 40),
            uid: Some(1000),
            gid: Some(100),
            permissions: Some(0o100644),
            atime: Some(1),
            mtime: Some(2),
        };
        let mut w = Writer::new();
        m.encode(&mut w);
        let mut r = Reader::new(w.as_slice());
        assert_eq!(Metadata::decode(&mut r).unwrap(), m);
        r.finish().unwrap();
    }

    #[test]
    fn partial_metadata_encodes_only_present_fields() {
        let m = Metadata {
            permissions: Some(0o755),
            ..Metadata::default()
        };
        let mut w = Writer::new();
        m.encode(&mut w);
        assert_eq!(w.as_slice(), [0, 0, 0, 4, 0, 0, 0x01, 0xED]);
        // uid ohne gid (und umgekehrt) lässt sich nicht darstellen und entfällt
        let m = Metadata {
            uid: Some(1),
            ..Metadata::default()
        };
        let mut w = Writer::new();
        m.encode(&mut w);
        assert_eq!(w.as_slice(), [0, 0, 0, 0]);
    }

    #[test]
    fn file_types_from_mode_bits() {
        let dir = Metadata {
            permissions: Some(0o040755),
            ..Metadata::default()
        };
        let file = Metadata {
            permissions: Some(0o100644),
            ..Metadata::default()
        };
        let link = Metadata {
            permissions: Some(0o120777),
            ..Metadata::default()
        };
        assert!(dir.is_dir() && !dir.is_file() && !dir.is_symlink());
        assert!(file.is_file() && !file.is_dir());
        assert!(link.is_symlink());
        assert!(!Metadata::default().is_file());
    }

    #[test]
    fn extended_attributes_are_skipped_and_unknown_flags_rejected() {
        let mut w = Writer::new();
        w.put_u32(ATTR_SIZE | ATTR_EXTENDED)
            .put_u64(7)
            .put_u32(1)
            .put_string(b"name")
            .put_string(b"value");
        let m = Metadata::decode(&mut Reader::new(w.as_slice())).unwrap();
        assert_eq!(m.size, Some(7));

        let mut w = Writer::new();
        w.put_u32(0x10);
        assert!(Metadata::decode(&mut Reader::new(w.as_slice())).is_err());

        // Behauptet Milliarden Erweiterungen bei wenigen Bytes.
        let mut w = Writer::new();
        w.put_u32(ATTR_EXTENDED).put_u32(u32::MAX);
        assert!(Metadata::decode(&mut Reader::new(w.as_slice())).is_err());
    }

    #[test]
    fn status_with_and_without_language_tag() {
        for lang in [true, false] {
            let (id, resp) = parse_response(&status_packet(9, 2, "gone", lang)).unwrap();
            assert_eq!(id, 9);
            match resp {
                Response::Status { status, message } => {
                    assert_eq!(status, SftpStatus::NoSuchFile);
                    assert_eq!(message, "gone");
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(SftpStatus::from(1), SftpStatus::Eof);
        assert_eq!(SftpStatus::from(99), SftpStatus::Other(99));
    }

    #[test]
    fn name_response_parses_entries() {
        let mut w = Writer::new();
        w.put_u8(FXP_NAME).put_u32(3).put_u32(2);
        for (name, size) in [("a.txt", 5u64), ("b", 6)] {
            w.put_string(name.as_bytes())
                .put_string(b"-rw-r--r-- long listing");
            Metadata {
                size: Some(size),
                ..Metadata::default()
            }
            .encode(&mut w);
        }
        let (id, resp) = parse_response(w.as_slice()).unwrap();
        assert_eq!(id, 3);
        let Response::Name(entries) = resp else {
            panic!()
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[1].metadata.size, Some(6));
    }

    #[test]
    fn hostile_counts_and_lengths_are_rejected() {
        // Viele Einträge angekündigt, keine vorhanden.
        let mut w = Writer::new();
        w.put_u8(FXP_NAME).put_u32(1).put_u32(u32::MAX);
        assert!(parse_response(w.as_slice()).is_err());

        // Handle über 256 Bytes.
        let mut w = Writer::new();
        w.put_u8(FXP_HANDLE).put_u32(1).put_string(&[0u8; 257]);
        assert!(parse_response(w.as_slice()).is_err());

        // Unbekannter Typ, abgeschnitten, Rest am Ende.
        assert!(parse_response(&[200, 0, 0, 0, 1]).is_err());
        assert!(parse_response(&[FXP_STATUS, 0, 0]).is_err());
        let mut w = Writer::new();
        w.put_u8(FXP_DATA).put_u32(1).put_string(b"x").put_u8(0);
        assert!(parse_response(w.as_slice()).is_err());
    }

    #[test]
    fn non_utf8_names_are_replaced() {
        let mut w = Writer::new();
        w.put_u8(FXP_NAME)
            .put_u32(1)
            .put_u32(1)
            .put_string(&[b'a', 0xff])
            .put_string(b"");
        Metadata::default().encode(&mut w);
        let Response::Name(entries) = parse_response(w.as_slice()).unwrap().1 else {
            panic!()
        };
        assert_eq!(entries[0].name, "a\u{fffd}");
    }
}
