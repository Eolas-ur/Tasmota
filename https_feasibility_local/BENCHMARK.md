# M5-00C HTTPS runtime benchmark procedure

**Do not run against the Athom plug at 172.18.10.69.**  
Use a USB-powered ESP8266/ESP8285 development board with serial access.

## Pass / fail taxonomy

| Class | Meaning |
|-------|---------|
| TLS transport failure | Handshake/alert/timeout; device stays up; `HttpsMetrics` ConnFail increases |
| HTTP application failure | TLS OK but UI/API/upload fails |
| Firmware / device failure | WDT, abort, reboot, hang; check `HTTPS: boot reset=` after reconnect |

## Serial / MQTT command

After boot with `env:tasmota-https-feasibility`:

```text
HttpsMetrics
```

Logs also emit `HTTPS:` lines for init, handshake ok/fail, and disconnect heap recovery.

## Test matrix (lab board only)

1. **TLS 1.2 negotiation** — `curl -vk --tlsv1.2 --tls-max 1.2 https://<ip>/`
2. **Reject insecure / unsupported** — `curl -vk --tlsv1.0 --tls-max 1.0 https://<ip>/` and TLS 1.1; record whether core accepts (known gap: server allows 1.0–1.2)
3. **ECDSA P-256 presentation** — inspect peer cert: `openssl s_client -connect <ip>:443 -servername <ip> </dev/null`
4. **Chrome / Firefox / curl** — load `https://<ip>/` (expect self-signed warning); confirm main UI
5. **Normal UI page load** — root, configuration pages used in lab; watch heap min
6. **Repeated connections** — 50× curl to `/`; compare ConnOk, HsMaxMs, HeapMin, FragMax
7. **Oversized TLS / HTTP** — large ClientHello not practical; send oversized HTTP body / long URL; note transport vs app failure
8. **Firmware upload** — Firmware Upgrade via HTTPS UI; distinguish upload TLS failure from flash verify failure
9. **Low-memory recovery** — with MQTT or other load if available; force connections until ConnFail; confirm device recovers without reboot (`Disconnects`, heap after disc)

## CPU frequency

Measure handshake HsMs at **80 MHz** then **160 MHz** (`CpuFrequency 160`) without changing flash image layout. Record both.

## Hardware requirements

- Prefer USB ESP8266 or ESP8285 **dev board** (NodeMCU / Wemos D1 mini class) with USB-serial
- Flash layout compatible with `esp8266_1M` (or document deviation)
- Locally recoverable (serial upload / USB power cycle)
- Final claim for production Athom ESP8285 requires a follow-up on that hardware class after lab board passes
