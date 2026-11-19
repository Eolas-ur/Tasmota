# Local HTTPS feasibility material

## Non-production certificates (gitignored)

Generate once (requires OpenSSL):

```text
python https_feasibility_local/scripts/generate_dev_certs.py
```

Produces:

- `certs/https_feasibility_certs.h` — **gitignored** (embeds PEM; do not commit)
- `certs/server.cert.pem` / `certs/server.key.pem` — **gitignored**

## Tracked helpers

- `BENCHMARK.md` — lab procedure
- `RECOVERY.md` — manager/OTA/fail-closed notes
- `scripts/bearssl_server_secure_*.py` — M5-00D TLS 1.2 + AEAD overlay (LGPL-derived transform)
- `scripts/generate_dev_certs.py` — non-production EC P-256 cert generation
- `tests/test_bearssl_server_overlay.py` — offline source tests

`framework_overlay/` is generated at build and gitignored. The global PlatformIO
`framework-arduinoespressif8266` package is never modified.

Do not flash the managed Athom plug at 172.18.10.69 with this image.
