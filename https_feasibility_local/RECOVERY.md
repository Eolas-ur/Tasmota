# Operational recovery notes (M5-00D)

## Current feasibility behaviour

| Mode | Behaviour under `USE_WEBSERVER_HTTPS` |
|------|--------------------------------------|
| Normal admin UI | Single TLS listener (port 443). Same handlers/auth as HTTP build (`WebPassword`). Not a second open admin surface. |
| Wi-Fi manager / captive | Still constructs TLS on port 80. Captive portals expect cleartext HTTP — **broken UX** until a dual-stack or staged design exists. |
| Firmware upgrade | `/u2` upload path remains registered over TLS. Large bodies + small RX buffers are a runtime risk (test on lab board). |
| TLS configure failure | Fail-closed: delete server object, leave `Web.state` off, no keyless listener. |
| `stack_thunk` OOM | Core `StackThunk.cpp` calls `abort()` — hard restart. Not soft-recoverable in stock core. |

## Production recovery pathway (proposal only — not implemented)

Goal: retain recovery without an unrestricted second admin interface.

1. **Primary:** HTTPS admin with authentication (existing WebPassword / future mandatory auth).
2. **Local-only recovery:** serial console / USB flash remains the guaranteed brick-recovery path.
3. **Optional staged cleartext:** time-limited or button-held HTTP **only** on AP/manager mode for captive provisioning, disabled once STA is configured — never a permanent parallel open admin port on LAN.
4. **TLS init failure:** keep fail-closed; surface a safe LED/serial fault; do not auto-open unauthenticated HTTP on LAN.
5. **Do not** add network-reset or credential-wiping recovery hooks in this feasibility branch.

## Secondary-stack failure

Document for operators: first `WiFiServerSecure` construction allocates 6200 bytes. If heap cannot satisfy it, device aborts. Lab tests must watch free heap before `StartWebserver`.
