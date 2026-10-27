# Beispiele

| Beispiel | Zweck |
|---|---|
| `wire_and_packet` | Wire-Format und Paketformat ohne Netzwerk |
| `handshake` | Handshake gegen einen echten SSH-Server |
| `auth` | Public-Key-Anmeldung (auch mit Passphrase-Key) |
| `exec` | Befehl ausführen, stdout/stderr/Exit-Code zurückgeben |
| `shell` | Interaktive Shell mit PTY (stdin -> Shell -> stdout) |

## Lokalen Test-sshd starten

```sh
sudo apt install openssh-server          # einmalig
mkdir -p /tmp/sshd-demo && cd /tmp/sshd-demo
ssh-keygen -q -t ed25519 -N '' -f host_ed25519
ssh-keygen -lf host_ed25519.pub          # zeigt den Fingerprint (SHA256:...)
sudo mkdir -p /run/sshd
sudo /usr/sbin/sshd -D -e -p 2222 -h $PWD/host_ed25519 -o ListenAddress=127.0.0.1 -o UsePAM=no
```

In einem zweiten Terminal:

```sh
cargo run --example handshake -- 127.0.0.1:2222 SHA256:<fingerprint von oben>
```

Für `auth` zusätzlich einen Benutzer-Key anlegen und eintragen:

```sh
ssh-keygen -q -t ed25519 -N 'meine passphrase' -f user_key
cat user_key.pub >> /tmp/sshd-demo/authorized_keys
# sshd mit -o AuthorizedKeysFile=/tmp/sshd-demo/authorized_keys -o StrictModes=no starten
SSH_KEY_PASSPHRASE='meine passphrase' \
  cargo run --example auth -- 127.0.0.1:2222 SHA256:<fingerprint> $(id -un) user_key
```

Danach lässt sich ein Befehl ausführen (gleiche Argumente wie bei `auth`, plus Befehl):

```sh
cargo run --example exec -- 127.0.0.1:2222 SHA256:<fingerprint> $(id -un) user_key "uname -a; ls /"
```

Und die Shell (Eingabe per Pipe, bei `exit` endet das Beispiel):

```sh
printf 'echo $TERM; stty size\nexit\n' | \
  cargo run --example shell -- 127.0.0.1:2222 SHA256:<fingerprint> $(id -un) user_key
```

Die Integrationstests (`cargo test`) starten ihren eigenen `sshd` automatisch
und überspringen sich, wenn er nicht installiert ist.
