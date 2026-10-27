//! Führt einen Befehl auf einem SSH-Server aus.
//!
//!     cargo run --example exec -- 127.0.0.1:22 SHA256:... benutzer ~/.ssh/id_ed25519 "uname -a"
//!
//! Passphrase eines verschlüsselten Keys: Umgebungsvariable `SSH_KEY_PASSPHRASE`.
//! Der Exit-Code des Programms entspricht dem des Remote-Befehls.

use std::io::Write;

use simple_ssh_lib::keys::PrivateKey;
use simple_ssh_lib::transport::HostKeyCheck;
use simple_ssh_lib::{Config, ExitStatus, Session};

#[tokio::main(flavor = "current_thread")]
async fn main() -> simple_ssh_lib::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [addr, fingerprint, user, key_path, command] = args.as_slice() else {
        eprintln!(
            "usage: exec <host:port> <SHA256:fingerprint> <user> <private-key-file> <command>"
        );
        std::process::exit(2);
    };

    let pem = std::fs::read_to_string(key_path)?;
    let passphrase = std::env::var("SSH_KEY_PASSPHRASE").ok();
    let key = PrivateKey::from_openssh(&pem, passphrase.as_deref().map(str::as_bytes))?;

    let config = Config::new(user, key, HostKeyCheck::Fingerprint(fingerprint.clone()));
    let session = Session::connect(addr, config).await?;
    let out = session.exec(command).await?;

    std::io::stdout().write_all(&out.stdout)?;
    std::io::stderr().write_all(&out.stderr)?;
    match out.exit {
        ExitStatus::Code(code) => std::process::exit(code as i32),
        ExitStatus::Signal(name) => {
            eprintln!("beendet durch Signal {name}");
            std::process::exit(128);
        }
        // `Unknown` und spätere Varianten: kein Status bekannt
        _ => std::process::exit(255),
    }
}
