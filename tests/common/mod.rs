//! Startet einen echten OpenSSH-`sshd` auf localhost.
//! Gibt `None` zurück, wenn `sshd` oder `ssh-keygen` fehlen; Tests überspringen sich dann.
//!
//! Erzeugt außerdem Test-Schlüssel: zwei autorisierte (ohne und mit Passphrase)
//! und einen nicht autorisierten.

#![allow(dead_code)] // nicht jeder Test nutzt alles

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const KEY_PASSPHRASE: &str = "hunter2";

#[derive(Clone, Copy)]
pub struct Options {
    pub pubkey_auth: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { pubkey_auth: true }
    }
}

pub struct TestSshd {
    child: Child,
    dir: PathBuf,
    pub port: u16,
    pub fingerprint: String,
    /// Benutzer, mit dem sshd läuft (nur dieser kann sich anmelden).
    pub user: String,
    /// Autorisierter Key ohne Passphrase (PEM).
    pub key_plain: String,
    /// Autorisierter Key mit Passphrase [`KEY_PASSPHRASE`] (PEM).
    pub key_encrypted: String,
    /// Gültiger Key, der nicht in `authorized_keys` steht (PEM).
    pub key_unauthorized: String,
}

fn find(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .map(Path::to_path_buf)
}

fn keygen(keygen: &Path, args: &[&str], file: &Path) -> Option<()> {
    let ok = Command::new(keygen)
        .args(["-q", "-t", "ed25519", "-f"])
        .arg(file)
        .args(args)
        .status()
        .ok()?
        .success();
    ok.then_some(())
}

impl TestSshd {
    pub fn start() -> Option<Self> {
        Self::start_with(Options::default())
    }

    pub fn start_with(opts: Options) -> Option<Self> {
        let sshd = find(&["/usr/sbin/sshd", "/usr/local/sbin/sshd"])?;
        let ssh_keygen = find(&["/usr/bin/ssh-keygen", "/usr/local/bin/ssh-keygen"])?;

        let port = TcpListener::bind("127.0.0.1:0")
            .ok()?
            .local_addr()
            .ok()?
            .port();
        let dir =
            std::env::temp_dir().join(format!("simple-ssh-lib-sshd-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let _ = std::fs::create_dir_all("/run/sshd");

        let host = dir.join("host_ed25519");
        keygen(&ssh_keygen, &["-N", ""], &host)?;
        let out = Command::new(&ssh_keygen)
            .arg("-lf")
            .arg(dir.join("host_ed25519.pub"))
            .output()
            .ok()?;
        let fingerprint = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .nth(1)?
            .to_string();

        let plain = dir.join("user_plain");
        let encrypted = dir.join("user_encrypted");
        let unauthorized = dir.join("user_unauthorized");
        keygen(&ssh_keygen, &["-N", ""], &plain)?;
        keygen(&ssh_keygen, &["-N", KEY_PASSPHRASE, "-a", "4"], &encrypted)?;
        keygen(&ssh_keygen, &["-N", ""], &unauthorized)?;
        let mut authorized = std::fs::read_to_string(dir.join("user_plain.pub")).ok()?;
        authorized += &std::fs::read_to_string(dir.join("user_encrypted.pub")).ok()?;
        let authorized_path = dir.join("authorized_keys");
        std::fs::write(&authorized_path, authorized).ok()?;

        let user = String::from_utf8(Command::new("id").arg("-un").output().ok()?.stdout)
            .ok()?
            .trim()
            .to_string();

        let config = dir.join("sshd_config");
        std::fs::write(
            &config,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nUsePAM no\n\
                 StrictModes no\nPermitRootLogin yes\nPasswordAuthentication no\n\
                 KbdInteractiveAuthentication no\nPubkeyAuthentication {}\n\
                 AuthorizedKeysFile {}\nAllowUsers {user}\n",
                host.display(),
                dir.join("sshd.pid").display(),
                if opts.pubkey_auth { "yes" } else { "no" },
                authorized_path.display(),
            ),
        )
        .ok()?;

        let child = Command::new(&sshd)
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let sshd = Self {
            child,
            port,
            fingerprint,
            user,
            key_plain: std::fs::read_to_string(&plain).ok()?,
            key_encrypted: std::fs::read_to_string(&encrypted).ok()?,
            key_unauthorized: std::fs::read_to_string(&unauthorized).ok()?,
            dir,
        };

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Some(sshd);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

impl Drop for TestSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
