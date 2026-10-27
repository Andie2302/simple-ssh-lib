# Test-Schlüssel

Alle Schlüssel hier sind **ausschließlich für Tests** erzeugt und schützen nichts.

| Datei | Inhalt | Passphrase |
|---|---|---|
| `ed25519_plain` | ed25519, unverschlüsselt | – |
| `ed25519_aes256ctr` | ed25519, `aes256-ctr` + bcrypt (4 Runden) | `correct horse` |
| `ed25519_aes256gcm` | ed25519, `aes256-gcm@openssh.com` (nicht unterstützt) | `x` |
| `rsa` | RSA 2048 (nicht unterstützt) | – |
