# Local HTTPS feasibility material

Place non-production ECDSA P-256 PEM material here as:

- `certs/https_feasibility_certs.h` (generated) — **gitignored**
- `certs/server.cert.pem` / `certs/server.key.pem` — **gitignored**

Tracked helpers:

- `BENCHMARK.md` — lab procedure
- `RECOVERY.md` — manager/OTA/fail-closed notes
- `scripts/bearssl_server_secure_*.py` — M5-00D TLS 1.2 + AEAD overlay (LGPL-derived transform)
- `tests/test_bearssl_server_overlay.py` — offline source tests

`framework_overlay/` is generated at build and gitignored.

Do not flash the managed Athom plug at 172.18.10.69 with this image.
