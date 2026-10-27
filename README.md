# simple-ssh-lib

Eine kleine, asynchrone **SSH-Client-Bibliothek für Rust** (tokio) – nach dem Vorbild von
WireGuard: wenig Funktionen, ein fester Satz moderner Algorithmen, **keine Verhandlung** und
klare Fehler statt Fallbacks.

> Status: Version 0.1, funktional vollständig für den beschriebenen Umfang und gegen
> OpenSSH getestet. Die Bibliothek wurde noch **nicht von Dritten geprüft** (Audit).
> Getestet wird mit der aktuellen stable-Toolchain (Rust 1.97); ältere Versionen sind
> nicht geprüft.

## Was sie kann

| Funktion | API |
|---|---|
| Befehl ausführen (stdout, stderr, Exit-Code, optional stdin) | `session.exec(..)`, `session.exec_with_input(..)` |
| Interaktive Shell mit PTY (`AsyncRead + AsyncWrite`, Größenänderung) | `session.shell(Pty::new(80, 24))` |
| SFTP v3: lesen, schreiben, auflisten, Attribute, anlegen, löschen, umbenennen | `session.sftp()` |
| Parallele Befehle, Shells und SFTP auf **einer** Verbindung | alle Methoden nehmen `&self` |
| Schlüsselwechsel nach Datenmenge oder Zeit, auch vom Server ausgelöst | automatisch |
| Fristen und Keepalive | `Config::timeout`, `Config::keepalive` |

## Was sie bewusst nicht kann

Server-Rolle, Passwort- und Keyboard-Interactive-Anmeldung, SSH-Agent, Port-Forwarding, X11,
SCP, Kompression, RSA- und ECDSA-Schlüssel, FIDO-Schlüssel, andere Algorithmen als unten.
Fehlt dem Server etwas davon, gibt es einen Fehler (`NoCommonAlgorithm`,
`PublicKeyAuthUnavailable`, `SftpUnavailable`, `UnsupportedKey`) – nie einen stillen Umweg.

## Algorithmen (je genau einer)

| Zweck | Wahl |
|---|---|
| Schlüsselaustausch | `curve25519-sha256` (+ Strict KEX gegen Terrapin, Pflicht) |
| Host-Key | `ssh-ed25519` |
| Verschlüsselung und Integrität | `chacha20-poly1305@openssh.com` |
| Kompression | keine |
| Anmeldung | `publickey` mit ed25519, auch mit Passphrase (`aes256-ctr` + `bcrypt`) |

Der Server muss Strict KEX anbieten (OpenSSH ab 9.6, oder ältere Versionen mit Terrapin-Patch). Die
Kryptografie kommt aus den RustCrypto- und dalek-Crates; das Protokoll ist selbst
geschrieben. Kein OpenSSL, kein `unsafe`.

## Schnellstart

```toml
[dependencies]
simple-ssh-lib = { git = "https://github.com/Andie2302/simple-ssh-lib" }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "io-util"] }
```

```rust
use simple_ssh_lib::{Config, HostKeyCheck, PrivateKey, Session};

#[tokio::main]
async fn main() -> simple_ssh_lib::Result<()> {
    let pem = std::fs::read_to_string("/home/ich/.ssh/id_ed25519")?;
    let key = PrivateKey::from_openssh(&pem, None)?; // Some(b"passphrase") bei verschlüsselten Keys

    // Fingerprint des Servers aus vertrauenswürdiger Quelle, z.B.:
    //   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
    let config = Config::new("ich", key, HostKeyCheck::Fingerprint("SHA256:...".into()));
    let session = Session::connect("server.example:22", config).await?;

    let out = session.exec("uname -a").await?;
    println!("{}", String::from_utf8_lossy(&out.stdout));

    let sftp = session.sftp().await?;
    sftp.write("/tmp/hallo.txt", b"Hallo!").await?;
    println!("{:?}", sftp.read("/tmp/hallo.txt").await?);
    Ok(())
}
```

Die Host-Key-Prüfung ist **Pflicht**: `HostKeyCheck::Fingerprint(..)` oder ein eigener
`HostKeyCheck::Callback(..)` (z.B. mit einer `known_hosts`-Datei). Einen „alles akzeptieren“-Modus
gibt es nicht.

## Beispiele

Im Ordner [`examples/`](examples/) liegen lauffähige Programme (`handshake`, `auth`, `exec`,
`shell`, `sftp`, `wire_and_packet`). Die [Anleitung dort](examples/README.md) zeigt, wie man
dafür einen lokalen Test-`sshd` startet.

```sh
cargo run --example exec -- 127.0.0.1:2222 SHA256:<fingerprint> benutzer ~/.ssh/id_ed25519 "uname -a"
```

## Tests

```sh
sudo apt install openssh-server     # nur für die Interop-Tests nötig
cargo test
```

* **Unit- und Protokolltests** (Wire-Format, Pakete, Schlüsselwechsel, SFTP-Parser,
  Kanalverwaltung) laufen ohne Netzwerk.
* **Fake-Server-Tests** prüfen feindliches Serververhalten (falsche Versionen, zu große Pakete,
  kurze Reads, vertauschte Antworten, abgebrochene Anfragen).
* **Interop-Tests** starten einen eigenen `sshd` auf `127.0.0.1` und testen Anmeldung, `exec`,
  Shell, SFTP, Schlüsselwechsel unter Last, Fristen und Keepalive. Ohne `sshd` werden sie
  übersprungen.
* **Robustheitstests** mutieren gültige Eingaben zufällig und erwarten: nie Panik, nie Hänger.
  Mehr Durchläufe: `FUZZ_ITERS=300000 cargo test --test robustness`.
* **Echtes Fuzzing** mit `cargo-fuzz` (nightly) beschreibt [`fuzz/README.md`](fuzz/README.md).

## Sicherheitshinweise

* Prüfe den Host-Key-Fingerprint über einen zweiten, vertrauenswürdigen Weg.
* Passphrasen gehören nicht in Argumentlisten; die Beispiele lesen `SSH_KEY_PASSPHRASE`.
* Speicher mit Schlüsselmaterial wird beim Freigeben überschrieben (`zeroize`); das schützt
  nicht gegen Angreifer mit Zugriff auf den Prozessspeicher.
* Grenzen gegen böswillige Server: Paketgröße, Fenstergrößen, Verzeichnisgröße,
  `Config::max_output`, bcrypt-Runden in Schlüsseldateien, Fristen beim Verbindungsaufbau.
* Hinweise auf Sicherheitslücken bitte nicht öffentlich posten, sondern die Maintainer direkt
  kontaktieren.

## Lizenz

Wahlweise unter [MIT](LICENSE-MIT) oder [Apache-2.0](LICENSE-APACHE).
