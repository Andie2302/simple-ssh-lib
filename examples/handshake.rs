//! Verbindet sich mit einem SSH-Server und führt den Handshake aus.
//!
//!     cargo run --example handshake -- 127.0.0.1:22 SHA256:...
//!
//! Ohne Fingerprint wird die Verbindung abgelehnt; die Fehlermeldung nennt
//! den Fingerprint des Servers. Prüfe ihn über einen vertrauenswürdigen Weg
//! (z.B. `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` auf dem Server)
//! und starte das Beispiel danach mit diesem Wert.

use simple_ssh_lib::transport::{HostKeyCheck, Transport};
use tokio::net::TcpStream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> simple_ssh_lib::Result<()> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:22".into());
    let expected = args.next().unwrap_or_default();

    let stream = TcpStream::connect(&addr).await?;
    let mut t = Transport::connect(stream, &HostKeyCheck::Fingerprint(expected)).await?;

    println!("server banner : {}", t.server_banner());
    println!("host key      : {}", t.host_key_fingerprint());
    println!("encrypted     : {}", t.is_encrypted());

    t.request_service("ssh-userauth").await?;
    println!("service       : ssh-userauth accepted (Anmeldung folgt in Meilenstein 3)");
    Ok(())
}
