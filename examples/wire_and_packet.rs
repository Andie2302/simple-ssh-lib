//! Zeigt Wire-Format und Packet-Layer anhand einer KEXINIT-ähnlichen Nachricht.
//!
//!     cargo run --example wire_and_packet

use simple_ssh_lib::transport::packet::{read_packet, write_packet};
use simple_ssh_lib::wire::{Reader, Writer};

const MSG_KEXINIT: u8 = 20;

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> simple_ssh_lib::Result<()> {
    // 1. Nachricht mit dem Writer bauen.
    let mut w = Writer::new();
    w.put_u8(MSG_KEXINIT)
        .put_raw(&[0u8; 16]) // Cookie (hier nur Platzhalter)
        .put_name_list(&["curve25519-sha256"])
        .put_name_list(&["ssh-ed25519"])
        .put_bool(false);
    let payload = w.into_vec();
    println!("payload ({} bytes):\n  {}\n", payload.len(), hex(&payload));

    // 2. Über einen In-Memory-Stream als SSH-Paket verschicken und lesen.
    let (mut client, mut server) = tokio::io::duplex(4096);
    write_packet(&mut client, &payload).await?;
    let received = read_packet(&mut server).await?;

    // 3. Mit dem Reader wieder zerlegen.
    let mut r = Reader::new(&received);
    println!("msg type : {}", r.get_u8()?);
    println!("cookie   : {}", hex(r.get_raw(16)?));
    println!("kex      : {:?}", r.get_name_list()?);
    println!("hostkey  : {:?}", r.get_name_list()?);
    println!("follows  : {}", r.get_bool()?);
    r.finish()?;
    Ok(())
}
