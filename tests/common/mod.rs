//! Startet einen echten OpenSSH-`sshd` auf localhost (nur Host-Key, keine Auth).
//! Gibt `None` zurück, wenn `sshd` oder `ssh-keygen` fehlen; Tests überspringen sich dann.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct TestSshd {
    child: Child,
    dir: PathBuf,
    pub port: u16,
    pub fingerprint: String,
}

fn find(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .map(Path::to_path_buf)
}

impl TestSshd {
    pub fn start() -> Option<Self> {
        let sshd = find(&["/usr/sbin/sshd", "/usr/local/sbin/sshd"])?;
        let keygen = find(&["/usr/bin/ssh-keygen", "/usr/local/bin/ssh-keygen"])?;

        let port = TcpListener::bind("127.0.0.1:0")
            .ok()?
            .local_addr()
            .ok()?
            .port();
        let dir =
            std::env::temp_dir().join(format!("simple-ssh-lib-sshd-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let _ = std::fs::create_dir_all("/run/sshd");

        let key = dir.join("host_ed25519");
        let ok = Command::new(&keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .ok()?
            .success();
        if !ok {
            return None;
        }
        let out = Command::new(&keygen)
            .arg("-lf")
            .arg(dir.join("host_ed25519.pub"))
            .output()
            .ok()?;
        let fingerprint = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .nth(1)?
            .to_string();

        let config = dir.join("sshd_config");
        std::fs::write(
            &config,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nUsePAM no\n",
                key.display(),
                dir.join("sshd.pid").display()
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
            dir,
            port,
            fingerprint,
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
