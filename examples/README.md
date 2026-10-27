# Beispiele

| Beispiel | Zweck |
|---|---|
| `wire_and_packet` | Wire-Format und Paketformat ohne Netzwerk |
| `handshake` | Handshake gegen einen echten SSH-Server |

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

Die Integrationstests (`cargo test`) starten ihren eigenen `sshd` automatisch
und überspringen sich, wenn er nicht installiert ist.
