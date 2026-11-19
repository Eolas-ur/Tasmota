# Local HTTPS feasibility material

Place non-production ECDSA P-256 PEM material here as:

- `certs/https_feasibility_certs.h` (generated) — **gitignored**
- `certs/server.cert.pem` / `certs/server.key.pem` — **gitignored**

Tracked helpers: `BENCHMARK.md` (lab procedure). Used only by `env:tasmota-https-feasibility`.
Do not flash the managed Athom plug at 172.18.10.69 with this image.
