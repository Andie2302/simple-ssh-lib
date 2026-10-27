//! Meldet sich per Public Key an einem SSH-Server an.
//!
//!     cargo run --example auth -- 127.0.0.1:22 SHA256:... benutzer ~/.ssh/id_ed25519
//!
//! Ist der Key verschlüsselt, wird die Passphrase aus der Umgebungsvariable
//! `SSH_KEY_PASSPHRASE` gelesen (nie als Argument, das landet in der Prozessliste).

use simple_ssh_lib::auth::authenticate;
use simple_ssh_lib::keys::PrivateKey;
use simple_ssh_lib::transport::{HostKeyCheck, Transport};
use tokio::net::TcpStream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> simple_ssh_lib::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [addr, fingerprint, user, key_path] = args.as_slice() else {
        eprintln!("usage: auth <host:port> <SHA256:fingerprint> <user> <private-key-file>");
        std::process::exit(2);
    };

    let pem = std::fs::read_to_string(key_path)?;
    let passphrase = std::env::var("SSH_KEY_PASSPHRASE").ok();
    let key = PrivateKey::from_openssh(&pem, passphrase.as_deref().map(str::as_bytes))?;
    println!("key           : {} ({})", key.fingerprint(), key.comment());

    let stream = TcpStream::connect(addr).await?;
    let mut t = Transport::connect(stream, &HostKeyCheck::Fingerprint(fingerprint.clone())).await?;
    println!("server        : {}", t.server_banner());

    authenticate(&mut t, user, &key).await?;
    println!("angemeldet als {user}");
    Ok(())
}
