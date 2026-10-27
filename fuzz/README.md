# Fuzzing mit cargo-fuzz

Coverage-gesteuertes Fuzzing der Parser, die Daten vom Server oder aus Dateien lesen.
Es braucht eine **nightly**-Toolchain und `cargo-fuzz`:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run sftp_response          # läuft, bis du abbrichst
cargo +nightly fuzz run mux_dispatch -- -max_total_time=300
```

| Ziel | Prüft |
|---|---|
| `wire_reader` | SSH-Datentypen (string, mpint, name-list, ...) |
| `packet_body` | unverschlüsseltes Paketformat |
| `kexinit` | KEXINIT des Servers (Handshake und Rekeying) |
| `ecdh_reply` | `SSH_MSG_KEX_ECDH_REPLY` |
| `host_signature` | Host-Key- und Signatur-Blob |
| `cipher_open` | verschlüsseltes Paket (Länge, Rumpf, Tag) |
| `sftp_response` | SFTP-Antwortpakete |
| `mux_dispatch` | Kanalnachrichten des Servers (Fenster, Daten, Requests) |
| `private_key` | OpenSSH-Private-Key-Dateien |
| `base64_decode` | Base64-Dekoder der Key-Datei |
| `banner` | Banner-Austausch (async) |
| `sftp_stream` | SFTP-Client gegen beliebige Server-Bytes (async) |

Die Einstiegspunkte stehen in `src/fuzz_api.rs`; ohne nightly läuft dieselbe Idee als
Zufalls-Mutationstest in `tests/robustness.rs` (`FUZZ_ITERS=300000 cargo test --test robustness`).

Gefundene Abstürze landen in `fuzz/artifacts/`. Bitte als Regressionstest übernehmen.
