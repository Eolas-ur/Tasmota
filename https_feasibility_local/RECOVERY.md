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

## Failure cases and recovery

| Failure | Effect |
|---------|--------|
| Crash / abort inside BearSSL / `stack_thunk` OOM before trial expiry | Device reboots; **trial is not persisted** → HTTPS stays off. |
| Confirmed HTTPS start fails (soft) | HTTP continues; after `HTTPS_FEASIBILITY_BOOT_FAIL_LIMIT` (3) start failures in one uptime, confirmed bit is cleared once via `SettingsSave`. |
| Confirmed HTTPS causes hard abort before suppression runs | May still boot-loop; prefer Trial validation before Confirm. Serial recovery remains the hard fallback. |
| Heap exhaustion starting listener | Start fails; HTTP remains up; error in `HttpsWeb` status. |
| Wi-Fi manager / captive | HTTPS listener suspended; confirmed persistence kept; restored when STA web returns. |

## Client transport note (M5-01B)

`Webserver->client()` returns a **reference** to the live request client so BearSSL
virtual `write`/`flush`/`stop` are preserved on HTTPS. Assigning into a `WiFiClient`
value object while `httpsServing()` slices TLS state and is unsupported.

## Operator guidance

1. Keep HTTP reachable on :80.
2. Run `HttpsWeb Trial`, test TLS from a lab client, watch heap/`HttpsMetrics`.
3. Only then `HttpsWeb Confirm`.
4. On problems: `HttpsWeb Off` over HTTP/MQTT/serial.

Do not flash the managed Athom plug at 172.18.10.69 with experimental images without a serial recovery plan.
