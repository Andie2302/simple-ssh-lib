//! Interaktive Shell mit PTY. Liest Eingaben von stdin und zeigt die Ausgabe an.
//!
//!     printf 'uname -a\nexit\n' | cargo run --example shell -- \
//!         127.0.0.1:22 SHA256:... benutzer ~/.ssh/id_ed25519
//!
//! Das Terminal selbst bleibt im normalen Zeilenmodus (kein Raw-Mode), das Beispiel
//! zeigt nur den Datenfluss. Passphrase eines Keys: `SSH_KEY_PASSPHRASE`.

use simple_ssh_lib::keys::PrivateKey;
use simple_ssh_lib::transport::HostKeyCheck;
use simple_ssh_lib::{Config, Pty, Session};
use tokio::io::{self, AsyncWriteExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> simple_ssh_lib::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [addr, fingerprint, user, key_path] = args.as_slice() else {
        eprintln!("usage: shell <host:port> <SHA256:fingerprint> <user> <private-key-file>");
        std::process::exit(2);
    };

    let pem = std::fs::read_to_string(key_path)?;
    let passphrase = std::env::var("SSH_KEY_PASSPHRASE").ok();
    let key = PrivateKey::from_openssh(&pem, passphrase.as_deref().map(str::as_bytes))?;
    let config = Config::new(user, key, HostKeyCheck::Fingerprint(fingerprint.clone()));
    let session = Session::connect(addr, config).await?;

    let shell = session.shell(Pty::default()).await?;
    let (mut from_shell, mut to_shell) = io::split(shell);

    // stdin -> Shell; bei Ende der Eingabe EOF senden.
    tokio::spawn(async move {
        let _ = io::copy(&mut io::stdin(), &mut to_shell).await;
        let _ = to_shell.shutdown().await;
    });

    // Shell -> stdout, bis der Server den Channel schließt.
    io::copy(&mut from_shell, &mut io::stdout()).await?;
    Ok(())
}
