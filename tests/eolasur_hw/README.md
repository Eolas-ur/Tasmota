# EolasUR Tasmota hardware regression harness

Read-only HTTP tests for a live Tasmota device. No firmware uploads, restarts, relay switching, or configuration changes.

## Layout

| Path | Role |
|------|------|
| `client.py` | HTTP GET `/cm` + console client |
| `model.py` | Snapshot extract + sanitisation |
| `compare.py` | Baseline comparison |
| `monitor.py` | Uptime / restart detection |
| `harness.py` | CLI modes |
| `run_harness.py` | Launcher |
| `fixtures/` | Synthetic baselines / Status samples (safe to commit) |
| `local/` | **Gitignored** private baselines, evidence, results |
| `test_harness_unit.py` | Offline unit tests |

## Requirements

- Python 3.9+
- Standard library only
- Device HTTP API reachable for live modes

## Configuration

```text
set TASMOTA_HOST=<device-host-or-ip>
set TASMOTA_BASELINE=tests/eolasur_hw/local/baselines/device-baseline.json
# optional HTTP basic auth (never written to artefacts):
set TASMOTA_USER=...
set TASMOTA_PASSWORD=...
```

Host and credentials are not hardcoded.

Private device baselines belong under `local/` (gitignored) or another path outside the repository. Do not commit real MAC/IP/SSID/MQTT host data.

## Modes

### Capture baseline (private)

```bash
python tests/eolasur_hw/run_harness.py --host %TASMOTA_HOST% capture-baseline ^
  --output tests/eolasur_hw/local/baselines/device-baseline.json
```

### Smoke

```bash
python tests/eolasur_hw/run_harness.py --host %TASMOTA_HOST% smoke ^
  --baseline tests/eolasur_hw/local/baselines/device-baseline.json ^
  --retain-infra
```

Without `--retain-infra`, written result JSON redacts host/MAC/SSID/IP-like fields.

### Stability

```bash
python tests/eolasur_hw/run_harness.py --host %TASMOTA_HOST% stability ^
  --duration 120 --interval 15 ^
  --baseline tests/eolasur_hw/local/baselines/device-baseline.json
```

### Post-deploy

Does **not** flash firmware.

```bash
python tests/eolasur_hw/run_harness.py --host %TASMOTA_HOST% post-deploy ^
  --baseline tests/eolasur_hw/local/baselines/device-baseline.json ^
  --expect-version "16.0.0.5(tasmota)" ^
  --expect-build "2026-11-18T17:07:44"
```

### Assess logs

```bash
python tests/eolasur_hw/run_harness.py --host %TASMOTA_HOST% assess-logs
```

## Offline unit tests

```bash
python -m unittest tests.eolasur_hw.test_harness_unit
```

(from repository root with `PYTHONPATH=tests`, or:)

```bash
cd tests
python -m unittest eolasur_hw.test_harness_unit
```

## Interpreting results

- Exit code `0` = PASS, non-zero = FAIL
- Missing required Status fields ⇒ FAIL (no false PASS)
- Unreachable device / malformed JSON ⇒ FAIL
- `findings[].result`: `match` | `warn` | `fail`

## Safety

GET-only HTTP. No OTA upload, `Restart`, `Reset`, `Power`, Wi-Fi changes, or settings restore.
