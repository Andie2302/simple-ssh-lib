//! Einstiegspunkte für Fuzzing und Robustheitstests: Jede Funktion bekommt beliebige
//! Bytes und darf weder abstürzen noch hängen noch riesige Mengen Speicher anlegen.
//!
//! Das ist keine stabile API; sie ist versteckt und nur für `tests/robustness.rs` und
//! die `cargo-fuzz`-Ziele in `fuzz/` gedacht.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::keys::PrivateKey;
use crate::sftp::Sftp;
use crate::transport::cipher::ChaChaPoly;
use crate::transport::{kex, kexinit, packet, version};
use crate::wire::Reader;

/// Alle Lesefunktionen des Wire-Formats, gesteuert von den Eingabebytes selbst.
pub fn wire_reader(data: &[u8]) {
    let mut r = Reader::new(data);
    for &op in data {
        let outcome = match op % 9 {
            0 => r.get_u8().map(|_| ()),
            1 => r.get_bool().map(|_| ()),
            2 => r.get_u32().map(|_| ()),
            3 => r.get_u64().map(|_| ()),
            4 => r.get_string().map(|_| ()),
            5 => r.get_str().map(|_| ()),
            6 => r.get_mpint().map(|_| ()),
            7 => r.get_name_list().map(|_| ()),
            _ => r.get_raw(usize::from(op)).map(|_| ()),
        };
        if outcome.is_err() {
            break;
        }
    }
    // Jede Funktion auch einzeln auf frischen Daten.
    let _ = Reader::new(data).get_mpint();
    let _ = Reader::new(data).get_name_list();
    let _ = Reader::new(data).get_str();
}

/// Unverschlüsselter Paketkörper (nach dem Längenfeld).
pub fn packet_body(data: &[u8]) {
    let _ = packet::decode_body(data);
    let _ = packet::unpad(data);
}

/// KEXINIT des Servers, im ersten Austausch und beim Rekeying.
pub fn kexinit(data: &[u8]) {
    let _ = kexinit::check_server_kexinit(data, true);
    let _ = kexinit::check_server_kexinit(data, false);
}

/// ECDH_REPLY des Servers.
pub fn ecdh_reply(data: &[u8]) {
    let _ = kex::parse_ecdh_reply(data);
}

/// Host-Key-Blob und Signatur-Blob, aus `data` in zwei Teile geschnitten.
pub fn host_signature(data: &[u8]) {
    let mid = data
        .first()
        .map_or(0, |&b| usize::from(b) % (data.len() + 1));
    let (blob, signature) = data.split_at(mid);
    let _ = kex::verify_signature(blob, &[0u8; 32], signature);
}

/// Ein verschlüsseltes Paket (Länge, Rumpf, Tag) mit festem Schlüssel.
pub fn cipher_open(data: &[u8]) {
    let cipher = ChaChaPoly::new(&[0x42; 64]);
    if data.len() < 4 + 16 {
        return;
    }
    let (head, rest) = data.split_at(4);
    let (body, tag) = rest.split_at(rest.len() - 16);
    let mut enc_len = [0u8; 4];
    enc_len.copy_from_slice(head);
    let mut tag_array = [0u8; 16];
    tag_array.copy_from_slice(tag);
    let _ = cipher.decrypt_len(0, &enc_len);
    let _ = cipher.open(0, &enc_len, body, &tag_array);
}

/// Antwortpaket des SFTP-Servers (ohne Längenfeld).
pub fn sftp_response(data: &[u8]) {
    let _ = crate::sftp::parse_response_for_fuzzing(data);
}

/// Nachricht des SSH-Servers an die Kanalverwaltung.
pub fn mux_dispatch(data: &[u8]) {
    crate::connection::fuzz_dispatch(data);
}

/// Inhalt einer OpenSSH-Private-Key-Datei.
pub fn private_key(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let _ = PrivateKey::from_openssh(&text, Some(b"password"));
    let _ = PrivateKey::from_openssh(&text, None);
}

/// Base64-Dekoder der Key-Datei.
pub fn base64_decode(data: &[u8]) {
    let _ = crate::keys::base64::decode(&String::from_utf8_lossy(data));
}

/// Der Server schickt `data` als Beginn der Verbindung (Banner-Austausch).
pub async fn banner(data: &[u8]) {
    let (mut client, mut server) = tokio::io::duplex(1 << 16);
    let data = data.to_vec();
    tokio::spawn(async move {
        let _ = server.write_all(&data).await;
        let _ = server.shutdown().await;
    });
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        version::exchange(&mut client, version::CLIENT_BANNER),
    )
    .await;
}

/// Der SFTP-Server antwortet nach gültigem Handshake mit beliebigen Bytes und legt auf.
pub async fn sftp_stream(data: &[u8]) {
    let (client, mut server) = tokio::io::duplex(1 << 16);
    let data = data.to_vec();
    tokio::spawn(async move {
        let mut init = [0u8; 9]; // Länge (4) + Typ (1) + Version (4)
        if server.read_exact(&mut init).await.is_err() {
            return;
        }
        let _ = server.write_all(&[0, 0, 0, 5, 2, 0, 0, 0, 3]).await; // VERSION 3
        let _ = server.write_all(&data).await;
        // Danach Verbindung schließen: Anfragen ohne passende Antwort enden mit einem Fehler.
    });
    if let Ok(sftp) = Sftp::from_stream(client).await {
        let _ = tokio::time::timeout(Duration::from_millis(500), sftp.metadata("/x")).await;
        let _ = tokio::time::timeout(Duration::from_millis(500), sftp.read("/y")).await;
    }
}
