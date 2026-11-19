# HTTPS runtime benchmark procedure (M5-00C/D/G/H)

**Do not run against the Athom plug at 172.18.10.69.**  
Use a USB-powered ESP8266/ESP8285 development board with serial access.

## Pass / fail taxonomy

| Class | Meaning |
|-------|---------|
| TLS handshake failure | `_wait_for_handshake()` failed or early TLS setup fail; `HsFail` increases |
| TLS handshake success | Overlay sets `HttpsFeasibilityTlsHsOk=1`; `HsOk` increases even if TCP drops immediately |
| HTTP application failure | TLS OK (`HsOk`) but UI/API/upload fails; `HttpClientPolls` may still increase |
| Unknown TLS outcome | No TLS attempt observed (`HsOk` unset); `HsUnknown` (not success) |
| Firmware / device failure | WDT, abort, reboot, hang; check `HTTPS: boot reset=` after reconnect |

## Memory measurement (M5-00G)

`HeapMinSampled` / `MaxBlockMin` are **checkpoint samples** (`PeakIsSampled=1`), not an
allocator high-water mark. Samples are taken before alloc, after I/O buffers, after
engine init, after handshake attempt, and after disconnect. Contiguous free block is
recorded via `ESP.getMaxFreeBlockSize()` at those points.

## Serial / MQTT command

After boot with `env:tasmota-https-feasibility`:

```text
HttpsMetrics
```

Fields of interest: `HsOk`, `HsFail`, `HsUnknown`, `HsMs`/`HsMaxMs`, `LastSslErr`,
`TransportConnected`, `HttpClientPolls` (webserver polls while a client remains
connected — not HTTP request counts), `HeapMinSampled`, `MaxBlockMin`, `PeakIsSampled`.

Logs also emit `HTTPS:` lines for init, handshake ok/fail, and disconnect heap recovery.

## Offline source checks (no device)

```text
python -m pytest https_feasibility_local/tests/ -v
```

Confirms the M5-00D overlay transform enforces TLS 1.2 + ECDHE-ECDSA-AES128-GCM, and
M5-00G/H handshake classification contracts. **Does not prove wire behaviour.**

## Test matrix (lab board only)

1. **TLS 1.2 negotiation** — `curl -vk --tlsv1.2 --tls-max 1.2 https://<ip>/`
2. **Reject TLS 1.0 / 1.1** — `curl -vk --tlsv1.0 --tls-max 1.0` and `--tlsv1.1 --tls-max 1.1` (expect fail after M5-00D)
3. **Cipher policy** — `openssl s_client -connect <ip>:443 -cipher 'ECDHE-ECDSA-AES128-GCM-SHA256' -tls1_2` (expect success); CBC-only attempt (expect fail)
4. **ECDSA P-256 presentation** — `openssl s_client -connect <ip>:443 </dev/null`
5. **Chrome / Firefox / curl** — load `https://<ip>/` (self-signed warning); confirm main UI
6. **Normal UI page load** — root + config pages; watch `HeapMinSampled`
7. **Repeated connections** — 50× curl to `/`; `HsOk`, `HsMaxMs`, `HeapMinSampled`, `FragMax`
8. **Oversized HTTP** — large body / long URL; classify transport vs app failure
9. **Firmware upload** — UI upgrade over HTTPS; distinguish TLS vs flash verify failure
10. **Low-memory recovery** — `HsFail` without reboot; heap after disconnect

## CPU frequency

Measure handshake HsMs at **80 MHz** then **160 MHz** (`CpuFrequency 160`) without changing flash layout.

## Hardware requirements

- Prefer USB ESP8266 or ESP8285 **dev board** with USB-serial
- Flash layout compatible with `esp8266_1M` (or document deviation)
- Locally recoverable (serial upload / USB power cycle)
- Final Athom ESP8285 claim requires follow-up after lab board passes
