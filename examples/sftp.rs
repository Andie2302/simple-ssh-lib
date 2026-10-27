//! SFTP: Verzeichnis auflisten, Datei herunterladen oder hochladen.
//!
//!     cargo run --example sftp -- <host:port> <SHA256:fingerprint> <user> <keyfile> ls  <pfad>
//!     cargo run --example sftp -- <host:port> <SHA256:fingerprint> <user> <keyfile> get <remote> <lokal>
//!     cargo run --example sftp -- <host:port> <SHA256:fingerprint> <user> <keyfile> put <lokal> <remote>
//!
//! Passphrase eines verschlüsselten Keys: Umgebungsvariable `SSH_KEY_PASSPHRASE`.
//! Fehlt das SFTP-Subsystem auf dem Server, endet das Programm mit einer Fehlermeldung.

use simple_ssh_lib::keys::PrivateKey;
use simple_ssh_lib::transport::HostKeyCheck;
use simple_ssh_lib::{Config, Session};

fn usage() -> ! {
    eprintln!(
        "usage: sftp <host:port> <SHA256:fingerprint> <user> <private-key-file> ls <path>\n       \
         sftp ... get <remote> <local>\n       sftp ... put <local> <remote>"
    );
    std::process::exit(2);
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> simple_ssh_lib::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [addr, fingerprint, user, key_path, command, rest @ ..] = args.as_slice() else {
        usage()
    };

    let pem = std::fs::read_to_string(key_path)?;
    let passphrase = std::env::var("SSH_KEY_PASSPHRASE").ok();
    let key = PrivateKey::from_openssh(&pem, passphrase.as_deref().map(str::as_bytes))?;
    let config = Config::new(user, key, HostKeyCheck::Fingerprint(fingerprint.clone()));
    let session = Session::connect(addr, config).await?;
    let sftp = session.sftp().await?;

    match (command.as_str(), rest) {
        ("ls", [path]) => {
            let mut entries = sftp.read_dir(path).await?;
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            for e in entries {
                let kind = if e.metadata.is_dir() {
                    'd'
                } else if e.metadata.is_symlink() {
                    'l'
                } else {
                    '-'
                };
                let mode = e.metadata.permissions.map_or(0, |p| p & 0o777);
                println!(
                    "{kind}{mode:03o} {:>12} {}",
                    e.metadata.size.unwrap_or(0),
                    e.name
                );
            }
        }
        ("get", [remote, local]) => {
            let data = sftp.read(remote).await?;
            std::fs::write(local, &data)?;
            println!("{} Bytes nach {local} geladen", data.len());
        }
        ("put", [local, remote]) => {
            let data = std::fs::read(local)?;
            sftp.write(remote, &data).await?;
            println!("{} Bytes nach {remote} hochgeladen", data.len());
        }
        _ => usage(),
    }
    Ok(())
}
