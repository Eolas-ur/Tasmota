# Operational recovery notes (M5-01A)

## Current behaviour (`USE_WEBSERVER_HTTPS`)

| Mode | Behaviour |
|------|-----------|
| Default boot | **HTTP :80 only.** HTTPS is compiled in but disabled (no TLS listener, no handshake buffers). |
| `HttpsWeb Trial` / `1` | Starts HTTPS :443 in RAM trial mode. **Not persisted.** Auto-reverts after `HTTPS_FEASIBILITY_TRIAL_SEC` (default 300). Reboot cancels trial. |
| `HttpsWeb Confirm` / `2` | Persists `Settings->sbflag1.https_webserver` and keeps listener. Survives reboot. |
| `HttpsWeb Off` / `0` | Stops listener; clears persisted bit. HTTP unaffected. |
| Wi-Fi manager / captive | Cleartext HTTP :80 (facade + `TasmotaHttpWebServer`). HTTPS is not started in manager modes. |
| HTTPS configure/start failure | Logged; **HTTP continues**. |
| Factory reset | Settings memset clears `https_webserver` → HTTPS stays off. |
| `HttpRedirectToHttps` | **Reserved / not implemented** (reports 0). |

## Authentication

HTTPS serves the same dispatch handlers as HTTP (core table). `WebPassword` / `WebAuthenticate` apply. This is not an open second admin surface.

Driver-added routes (`FUNC_WEB_ADD_HANDLER`) are registered on HTTP at startup; HTTPS late-bind currently receives the core dispatch table only (documented limitation).

## Failure cases not auto-recoverable

| Failure | Effect |
|---------|--------|
| Crash / abort inside BearSSL / `stack_thunk` OOM before trial expiry | Device reboots; **trial is not persisted** → HTTPS stays off. Confirmed mode would retry HTTPS after reboot (may loop if HTTPS itself causes abort). |
| Confirmed HTTPS causes boot-time abort | May require serial reflash or safe mode; Quick Power Cycle / button alone is not the designed recovery. Prefer trial validation before Confirm. |
| Heap exhaustion starting listener | Start fails; HTTP remains up; error in `HttpsWeb` status. |

## Operator guidance

1. Keep HTTP reachable on :80.
2. Run `HttpsWeb Trial`, test TLS from a lab client, watch heap/`HttpsMetrics`.
3. Only then `HttpsWeb Confirm`.
4. On problems: `HttpsWeb Off` over HTTP/MQTT/serial.

Do not flash the managed Athom plug at 172.18.10.69 with experimental images without a serial recovery plan.
