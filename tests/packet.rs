//! Unverschlüsseltes Paketformat (RFC 4253 §6).

use simple_ssh_lib::Error;
use simple_ssh_lib::transport::packet::{
    MAX_PACKET_LEN, decode_body, encode, encode_with_padding, read_packet, write_packet,
};

const PAD: [u8; 16] = [0xAA; 16];

#[test]
fn layout_and_alignment() {
    // Payload 1 Byte: 4 + 1 + 1 = 6 -> 2 Padding wären zu wenig, also 10.
    let p = encode_with_padding(&[21], &PAD).unwrap();
    assert_eq!(p.len() % 8, 0);
    assert_eq!(&p[..4], &((p.len() - 4) as u32).to_be_bytes());
    assert_eq!(p[4], 10);
    assert_eq!(p[5], 21);
    assert!(p[6..].iter().all(|&b| b == 0xAA));
}

#[test]
fn every_payload_length_roundtrips_aligned_with_min_padding() {
    for n in 0..64 {
        let payload: Vec<u8> = (0..n as u8).collect();
        let p = encode(&payload).unwrap();
        assert_eq!(p.len() % 8, 0, "len {n}");
        assert!(p[4] >= 4, "padding too small for len {n}");
        assert_eq!(decode_body(&p[4..]).unwrap(), payload);
    }
}

#[test]
fn rejects_malformed_bodies() {
    // nicht auf 8 ausgerichtet
    assert!(matches!(
        decode_body(&[4, 1, 0, 0, 0, 0, 0]),
        Err(Error::InvalidPacket(_))
    ));
    // Padding < 4
    assert!(matches!(
        decode_body(&[3, 0, 0, 0]),
        Err(Error::InvalidPacket(_))
    ));
    // Padding größer als Rest
    assert!(matches!(
        decode_body(&[200, 0, 0, 0, 0, 0, 0, 0]),
        Err(Error::InvalidPacket(_))
    ));
}

#[test]
fn oversized_payload_is_rejected() {
    let big = vec![0u8; MAX_PACKET_LEN];
    assert!(matches!(encode(&big), Err(Error::InvalidPacket(_))));
}

#[tokio::test]
async fn write_then_read_over_duplex() {
    let (mut a, mut b) = tokio::io::duplex(1024);
    write_packet(&mut a, b"hello").await.unwrap();
    write_packet(&mut a, b"").await.unwrap();
    assert_eq!(read_packet(&mut b).await.unwrap(), b"hello");
    assert_eq!(read_packet(&mut b).await.unwrap(), b"");
}

#[tokio::test]
async fn reader_rejects_huge_length_before_allocating() {
    use tokio::io::AsyncWriteExt;
    let (mut a, mut b) = tokio::io::duplex(64);
    a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    assert!(matches!(
        read_packet(&mut b).await,
        Err(Error::InvalidPacket(_))
    ));
}

#[tokio::test]
async fn truncated_stream_is_io_error() {
    use tokio::io::AsyncWriteExt;
    let (mut a, mut b) = tokio::io::duplex(64);
    a.write_all(&[0, 0, 0, 16, 4]).await.unwrap();
    drop(a);
    assert!(matches!(read_packet(&mut b).await, Err(Error::Io(_))));
}
