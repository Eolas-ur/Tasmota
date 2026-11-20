# Operational recovery notes (M5-01A / M5-01D)

## Current behaviour (`USE_WEBSERVER_HTTPS`)

| Mode | Behaviour |
|------|-----------|
| Default boot | **HTTP :80 only.** HTTPS is compiled in but disabled (no TLS listener, no handshake buffers). |
| `HttpsWeb Trial` / `1` | Starts HTTPS :443 in RAM trial mode. **Not persisted.** Auto-reverts after `HTTPS_FEASIBILITY_TRIAL_SEC` (default 300). Reboot cancels trial. |
| `HttpsWeb Confirm` / `2` | Persists `Settings->sbflag1.https_webserver` and keeps listener. Survives reboot. |
| `HttpsWeb Off` / `0` | Stops listener; clears persisted bit. HTTP unaffected. If issued over HTTPS, stop is **deferred** until the response completes. |
| Wi-Fi manager / captive | Cleartext HTTP :80 (facade + `TasmotaHttpWebServer`). HTTPS is suspended (deferred if a TLS handler is active). |
| HTTPS configure/start failure | Logged; **HTTP continues**. |
| Factory reset | Settings memset clears `https_webserver` → HTTPS stays off. |
| `HttpRedirectToHttps` | **Reserved / not implemented** (reports 0). |

## Listener lifecycle (M5-01D)

While `httpsServing()` is true, HTTPS must not destroy its own `TasmotaHttpsWebServer` or the active TLS client. `HttpsFeasibilityStopListener` / Trial restart / manager suspend set a pending op; `HttpsFeasibilityProcessDeferred` runs after `setHttpsServing(false)` in `PollDnsWebserver` (and from `EverySecond`).

Outstanding response completes first; then the HTTPS server object is `close()`d and `delete`d. No blocking delay and no reboot required.

## Handler ownership

- HTTP `on()` / `addHandler()` registrations at startup remain on the HTTP server for the process lifetime.
- HTTPS rebind (`WebServerRegisterRoutesForHttps`) registers core `on()` routes onto a **new** HTTPS server only (`TASMOTA_WEB_ROUTE_HTTPS`).
- `addHandler()` is HTTP-typed and cannot attach to the HTTPS template server. When the route target is HTTPS-only, `addHandler` **skips without deleting** the pointer (avoids UAF if HTTP already owns it). Callers must not `new` a second HTTP-typed handler solely for HTTPS rebind — use `on()`.
- Deleting the HTTPS server frees its `on()`-created handlers. Repeated Trial/Off cycles replace the HTTPS instance; HTTP routes are not duplicated.

## Heap recovery after `HttpsWeb Off`

Expected reclaim: TLS server object, per-connection buffers, and route handlers on that instance.

**Intentionally retained** (not a leak of the Off path):

- Parsed cert (`X509List`) and private key (`PrivateKey`) — `HttpsFeasibilityReady` / `CertCache:1` for reuse on the next Trial.
- BearSSL secondary stack / `stack_thunk` may linger briefly after client teardown.

Do **not** expect free heap to return to the pre-first-Trial baseline after Off. Status JSON reports `CertCache`.

## Authentication

HTTPS serves the same dispatch handlers as HTTP (core table). `WebPassword` / `WebAuthenticate` apply. This is not an open second admin surface.

Driver-added routes (`FUNC_WEB_ADD_HANDLER`) registered via `on()` are rebound on HTTPS late-bind; `addHandler()`-based routes remain HTTP-only.

## Failure cases and recovery

| Failure | Effect |
|---------|--------|
| Crash / abort inside BearSSL / `stack_thunk` OOM before trial expiry | Device reboots; **trial is not persisted** → HTTPS stays off. |
| Confirmed HTTPS **listener init** fails (soft) | HTTP continues; after `HTTPS_FEASIBILITY_BOOT_FAIL_LIMIT` (3) start failures in one uptime, confirmed bit is cleared once via `SettingsSave`. TLS handshake failures do **not** increment this counter. |
| Confirmed HTTPS causes hard abort / WDT before suppression runs | May still boot-loop; prefer Trial validation before Confirm. Serial recovery remains the hard fallback. |
| Heap exhaustion starting listener | Start fails; HTTP remains up; error in `HttpsWeb` status. |
| Wi-Fi manager / captive | HTTPS listener suspended; confirmed persistence kept; restored when STA web returns. |

## Client transport note (M5-01B / M5-01D)

`Webserver->client()` returns a **reference** to the live request client so BearSSL
virtual `write`/`flush`/`stop` are preserved on HTTPS. Assigning into a `WiFiClient`
value object while `httpsServing()` slices TLS state and is unsupported. Streaming
call sites use `auto &` for ESP8266 `WiFiClient` / ESP32 `NetworkClient` portability.

## Operator guidance

1. Keep HTTP reachable on :80.
2. Run `HttpsWeb Trial`, test TLS from a lab client, watch heap/`HttpsMetrics`.
3. Only then `HttpsWeb Confirm`.
4. On problems: `HttpsWeb Off` over HTTP/MQTT/serial (or HTTPS — stop completes after the response).

Do not flash the managed Athom plug at 172.18.10.69 with experimental images without a serial recovery plan.
