//! Wire-Format gegen die Beispiele aus RFC 4251 §5.

use simple_ssh_lib::Error;
use simple_ssh_lib::wire::{Reader, Writer};

#[test]
fn string_example_from_rfc() {
    let mut w = Writer::new();
    w.put_string(b"testing");
    assert_eq!(
        w.as_slice(),
        [0, 0, 0, 7, b't', b'e', b's', b't', b'i', b'n', b'g']
    );
}

#[test]
fn name_list_examples_from_rfc() {
    let mut w = Writer::new();
    w.put_name_list(&[]);
    assert_eq!(w.as_slice(), [0, 0, 0, 0]);

    let mut w = Writer::new();
    w.put_name_list(&["zlib", "none"]);
    assert_eq!(
        w.as_slice(),
        [
            0, 0, 0, 9, b'z', b'l', b'i', b'b', b',', b'n', b'o', b'n', b'e'
        ]
    );

    let mut r = Reader::new(w.as_slice());
    assert_eq!(r.get_name_list().unwrap(), ["zlib", "none"]);
    r.finish().unwrap();
}

#[test]
fn mpint_examples_from_rfc() {
    let cases: &[(&[u8], &[u8])] = &[
        (&[], &[0, 0, 0, 0]),
        (
            &[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7],
            &[0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7],
        ),
        (&[0x80], &[0, 0, 0, 2, 0x00, 0x80]),
        (
            &[0xde, 0xad, 0xbe, 0xef],
            &[0, 0, 0, 5, 0x00, 0xde, 0xad, 0xbe, 0xef],
        ),
    ];
    for (input, encoded) in cases {
        let mut w = Writer::new();
        w.put_mpint(input);
        assert_eq!(w.as_slice(), *encoded);
        assert_eq!(Reader::new(encoded).get_mpint().unwrap(), *input);
    }
}

#[test]
fn mpint_strips_leading_zeros_on_write() {
    let mut w = Writer::new();
    w.put_mpint(&[0, 0, 0x7f]);
    assert_eq!(w.as_slice(), [0, 0, 0, 1, 0x7f]);
}

#[test]
fn mpint_rejects_negative_and_non_minimal() {
    // -1234 aus dem RFC
    let neg = [0, 0, 0, 2, 0xed, 0xcc];
    assert!(matches!(
        Reader::new(&neg).get_mpint(),
        Err(Error::Malformed(_))
    ));
    // 0x00 0x7f hätte ohne führende Null kodiert werden müssen
    let padded = [0, 0, 0, 2, 0x00, 0x7f];
    assert!(matches!(
        Reader::new(&padded).get_mpint(),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn integers_and_bool_roundtrip() {
    let mut w = Writer::new();
    w.put_u8(20)
        .put_bool(true)
        .put_u32(0xdead_beef)
        .put_u64(1 << 40);
    let mut r = Reader::new(w.as_slice());
    assert_eq!(r.get_u8().unwrap(), 20);
    assert!(r.get_bool().unwrap());
    assert_eq!(r.get_u32().unwrap(), 0xdead_beef);
    assert_eq!(r.get_u64().unwrap(), 1 << 40);
    r.finish().unwrap();
}

#[test]
fn strict_bool() {
    assert!(matches!(
        Reader::new(&[2]).get_bool(),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn truncated_and_trailing_input() {
    // String behauptet 10 Bytes, es gibt nur 2.
    let short = [0, 0, 0, 10, 1, 2];
    assert!(matches!(
        Reader::new(&short).get_string(),
        Err(Error::UnexpectedEof)
    ));
    assert!(matches!(
        Reader::new(&[0, 0]).get_u32(),
        Err(Error::UnexpectedEof)
    ));

    let mut r = Reader::new(&[1, 2, 3]);
    r.get_u8().unwrap();
    assert!(matches!(r.finish(), Err(Error::TrailingData(2))));
}

#[test]
fn invalid_utf8_is_rejected() {
    let bad = [0, 0, 0, 1, 0xff];
    assert!(matches!(
        Reader::new(&bad).get_str(),
        Err(Error::Malformed(_))
    ));
}
