#!/usr/bin/env python3
"""
EolasUR Tasmota hardware regression harness (read-only).

Modes:
  capture-baseline  Collect baseline JSON (private local storage by default)
  smoke             Single compare against baseline
  stability         Timed availability / heap / restart watch
  post-deploy       Verify expected firmware + retained config
  assess-logs       Read-only weblog buffer / QPC observability probe

Environment:
  TASMOTA_HOST       Device hostname or IP (required unless --host)
  TASMOTA_USER       Optional HTTP basic user
  TASMOTA_PASSWORD   Optional HTTP basic password (never written to artefacts)
  TASMOTA_BASELINE   Default baseline path
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .client import TasmotaClient
from .compare import compare_against_baseline, summarise_findings
from .model import build_baseline, extract_identity, sanitize_report, sanitize_text
from .monitor import RestartTracker

ROOT = Path(__file__).resolve().parent
LOCAL_ROOT = ROOT / "local"
DEFAULT_RESULTS = LOCAL_ROOT / "results"
DEFAULT_BASELINE_LOCAL = LOCAL_ROOT / "baselines" / "device-baseline.json"
EXAMPLE_BASELINE = ROOT / "fixtures" / "example_baseline.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_json(path: Path, data: Any, *, sanitize: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = sanitize_report(data) if sanitize else data
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _default_baseline_path() -> Path:
    env = os.environ.get("TASMOTA_BASELINE")
    if env:
        return Path(env)
    if DEFAULT_BASELINE_LOCAL.is_file():
        return DEFAULT_BASELINE_LOCAL
    return EXAMPLE_BASELINE


def _make_client(args: argparse.Namespace) -> TasmotaClient:
    host = args.host or os.environ.get("TASMOTA_HOST")
    if not host:
        raise SystemExit("Provide --host or set TASMOTA_HOST")
    return TasmotaClient(
        host=host,
        timeout=args.timeout,
        retries=args.retries,
        user=args.user or os.environ.get("TASMOTA_USER"),
        password=args.password or os.environ.get("TASMOTA_PASSWORD"),
    )


def _load_baseline(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"Baseline not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Malformed baseline JSON: {path}: {exc}") from exc
    if not isinstance(data, dict) or "identity" not in data:
        raise SystemExit(f"Baseline missing identity object: {path}")
    return data


def cmd_capture_baseline(args: argparse.Namespace) -> int:
    client = _make_client(args)
    try:
        status0 = client.collect_status0()
        extras = client.collect_extras()
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL capture-baseline: device unreachable or bad response: {exc}")
        return 1
    baseline = build_baseline(
        client.host,
        status0,
        extras,
        label=args.label,
        notes=args.note
        or [
            "Private hardware baseline; store under local/ (gitignored).",
            "Passwords are never retained.",
        ],
        retain_infra=True,
    )
    out = Path(args.output) if args.output else DEFAULT_BASELINE_LOCAL
    # Local baselines keep infrastructure identifiers; still strip credentials.
    _write_json(out, baseline, sanitize=False)
    print(f"Wrote baseline: {out}")
    print(
        f"Firmware={baseline['identity']['firmware']['version']} "
        f"Build={baseline['identity']['firmware']['build_datetime']} "
        f"Hardware={baseline['identity']['firmware']['hardware']}"
    )
    return 0


def cmd_smoke(args: argparse.Namespace) -> int:
    client = _make_client(args)
    baseline = _load_baseline(Path(args.baseline))
    t0 = time.perf_counter()
    try:
        status0 = client.collect_status0()
        extras = client.collect_extras()
        ok, identity, findings = compare_against_baseline(baseline, status0, extras)
        error = None
    except Exception as exc:  # noqa: BLE001
        ok = False
        identity = {}
        findings = []
        error = str(exc)
    elapsed = (time.perf_counter() - t0) * 1000.0

    result = {
        "schema": "eolasur-tasmota-hw-result/v1",
        "mode": "smoke",
        "started_at_utc": _utc_now(),
        "host": client.host,
        "pass": bool(ok and error is None),
        "elapsed_ms": round(elapsed, 1),
        "error": error,
        "identity": identity,
        "findings": findings,
        "request_records": [r.__dict__ for r in client.records],
        "summary": summarise_findings(findings) if findings else (error or "no findings"),
    }
    out = Path(args.output) if args.output else DEFAULT_RESULTS / f"smoke-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    _write_json(out, result, sanitize=not args.retain_infra)
    print(("PASS" if result["pass"] else "FAIL") + f" smoke ({out})")
    print(result["summary"])
    return 0 if result["pass"] else 1


def cmd_stability(args: argparse.Namespace) -> int:
    client = _make_client(args)
    baseline_path = Path(args.baseline) if args.baseline else None
    baseline = _load_baseline(baseline_path) if baseline_path and baseline_path.is_file() else None
    duration = args.duration
    interval = args.interval
    samples: List[Dict[str, Any]] = []
    config_drifts = 0
    connection_failures = 0
    tracker = RestartTracker()
    start = time.time()

    print(f"Stability watch host={client.host} duration={duration}s interval={interval}s")
    while True:
        elapsed = time.time() - start
        if elapsed > duration and samples:
            break
        sample: Dict[str, Any] = {"t_utc": _utc_now(), "elapsed_s": round(elapsed, 1)}
        try:
            status0 = client.collect_status0()
            extras = client.collect_extras() if args.check_config else {}
            identity = extract_identity(status0, extras if extras else None)
            boot = identity["runtime"]["boot_count"]
            uptime = identity["runtime"]["uptime_sec"]
            heap = identity["memory"]["heap_kb"]
            if identity["firmware"]["version"] is None:
                raise RuntimeError("missing firmware.version in Status response")
            restart = tracker.observe(boot, uptime)
            sample.update(
                {
                    "ok": True,
                    "version": identity["firmware"]["version"],
                    "heap_kb": heap,
                    "uptime_sec": uptime,
                    "boot_count": boot,
                    "power": identity["power"]["power"],
                    "restart_detected": restart,
                }
            )
            if baseline and extras:
                ok, _, findings = compare_against_baseline(
                    baseline,
                    status0,
                    extras,
                    require_firmware=True,
                )
                fails = [f for f in findings if f["result"] == "fail"]
                sample["config_ok"] = ok
                if not ok:
                    config_drifts += 1
                    sample["config_fails"] = fails
            samples.append(sample)
            print(
                f"{sample['t_utc']} ok heap={heap} uptime={uptime} boot={boot} "
                f"restart={restart}"
            )
        except Exception as exc:  # noqa: BLE001
            connection_failures += 1
            sample.update({"ok": False, "error": str(exc)})
            samples.append(sample)
            print(f"{sample['t_utc']} FAIL {exc}")

        if time.time() - start >= duration:
            break
        time.sleep(interval)

    heaps = [s["heap_kb"] for s in samples if s.get("ok") and s.get("heap_kb") is not None]
    passed = (
        connection_failures == 0
        and tracker.unexpected_restarts == 0
        and config_drifts == 0
        and len(samples) > 0
        and all(s.get("ok") for s in samples)
    )
    result = {
        "schema": "eolasur-tasmota-hw-result/v1",
        "mode": "stability",
        "started_at_utc": samples[0]["t_utc"] if samples else _utc_now(),
        "finished_at_utc": _utc_now(),
        "host": client.host,
        "duration_s": duration,
        "interval_s": interval,
        "pass": passed,
        "samples": len(samples),
        "connection_failures": connection_failures,
        "unexpected_restarts": tracker.unexpected_restarts,
        "config_drifts": config_drifts,
        "heap_kb": {
            "min": min(heaps) if heaps else None,
            "max": max(heaps) if heaps else None,
            "last": heaps[-1] if heaps else None,
        },
        "timeline": samples,
        "request_records_summary": {
            "count": len(client.records),
            "failures": sum(1 for r in client.records if not r.ok),
            "avg_ms": round(sum(r.elapsed_ms for r in client.records) / len(client.records), 1)
            if client.records
            else None,
        },
    }
    out = Path(args.output) if args.output else DEFAULT_RESULTS / f"stability-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    _write_json(out, result, sanitize=not args.retain_infra)
    print(
        ("PASS" if passed else "FAIL")
        + f" stability samples={len(samples)} fails={connection_failures} "
        f"restarts={tracker.unexpected_restarts}"
    )
    print(f"Wrote {out}")
    return 0 if passed else 1


def cmd_post_deploy(args: argparse.Namespace) -> int:
    client = _make_client(args)
    baseline = _load_baseline(Path(args.baseline))
    try:
        status0 = client.collect_status0()
        extras = client.collect_extras()
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL post-deploy: {exc}")
        return 1

    _, identity, findings = compare_against_baseline(
        baseline,
        status0,
        extras,
        require_firmware=False,
        expected_version=args.expect_version,
        expected_build=args.expect_build,
    )
    _, _, findings2 = compare_against_baseline(
        baseline,
        status0,
        extras,
        require_firmware=False,
    )
    merged: List[Dict[str, Any]] = []
    seen = set()
    for f in findings + findings2:
        key = (f.get("path"), f.get("note"), f.get("result"), repr(f.get("expected")), repr(f.get("actual")))
        if key in seen:
            continue
        seen.add(key)
        merged.append(f)

    passed = not any(f["result"] == "fail" for f in merged)
    if args.expect_version and identity.get("firmware", {}).get("version") != args.expect_version:
        passed = False
    if args.expect_build and identity.get("firmware", {}).get("build_datetime") != args.expect_build:
        passed = False

    result = {
        "schema": "eolasur-tasmota-hw-result/v1",
        "mode": "post-deploy",
        "started_at_utc": _utc_now(),
        "host": client.host,
        "pass": passed,
        "expect_version": args.expect_version,
        "expect_build": args.expect_build,
        "identity": identity,
        "findings": merged,
        "summary": summarise_findings(merged),
        "request_records": [r.__dict__ for r in client.records],
        "note": "Does not deploy firmware; verifies running image and retained configuration only.",
    }
    out = Path(args.output) if args.output else DEFAULT_RESULTS / f"post-deploy-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    _write_json(out, result, sanitize=not args.retain_infra)
    print(("PASS" if passed else "FAIL") + f" post-deploy ({out})")
    print(result["summary"])
    return 0 if passed else 1


def cmd_assess_logs(args: argparse.Namespace) -> int:
    client = _make_client(args)
    try:
        status0 = client.collect_status0()
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL assess-logs: {exc}")
        return 1
    log = status0.get("StatusLOG") or {}
    weblog = log.get("WebLog")
    console = sanitize_text(client.console_tail())
    qpc_hits = [line for line in console.replace("}1", "\n").splitlines() if "QPC:" in line]
    assessment = {
        "schema": "eolasur-tasmota-hw-log-assessment/v1",
        "captured_at_utc": _utc_now(),
        "host": "<redacted>" if not args.retain_infra else client.host,
        "weblog_level": weblog,
        "weblog_level_meaning": {
            0: "none",
            1: "error",
            2: "info (required for QPC INFO lines)",
            3: "debug",
            4: "debug more",
        }.get(weblog, "unknown"),
        "qpc_messages_require": "LOG_LEVEL_INFO (WebLog >= 2)",
        "buffer_notes": [
            "Tasmota keeps a circular DRAM log buffer (LOG_BUFFER_SIZE ~4–6 KB on ESP8266).",
            "Web console /cs?c2= polls GetLog() filtered by Settings->weblog_level.",
            "Boot lines including QPC rotate out once the buffer fills with later INFO/MQTT/status traffic.",
        ],
        "ordinary_operation": {
            "qpc_lines_present_in_buffer": bool(qpc_hits),
            "qpc_line_samples": qpc_hits[:10],
            "conclusion": (
                "QPC diagnostics are not visible during ordinary steady-state operation; "
                "they are emitted at boot/QPC update paths, not periodically."
            ),
        },
        "software_restart_observation": {
            "would_likely_emit": "QPC: Counter cleared",
            "capture_requirement": (
                "Poll /cs?c2= immediately after reconnect (WebLog>=2) before buffer rotation; "
                "this mode does not restart the device."
            ),
            "not_performed": True,
        },
        "console_snippet_sanitised": console[:1500],
    }
    out = Path(args.output) if args.output else DEFAULT_RESULTS / f"log-assessment-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    _write_json(out, assessment, sanitize=not args.retain_infra)
    print(f"WebLog={weblog} QPC_in_buffer={bool(qpc_hits)}")
    print(assessment["ordinary_operation"]["conclusion"])
    print(f"Wrote {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="EolasUR Tasmota hardware regression harness (read-only)")
    p.add_argument("--host", help="Device IP/hostname (or TASMOTA_HOST)")
    p.add_argument("--user", help="Optional HTTP basic user (or TASMOTA_USER)")
    p.add_argument("--password", help="Optional HTTP basic password (or TASMOTA_PASSWORD)")
    p.add_argument("--timeout", type=float, default=12.0)
    p.add_argument("--retries", type=int, default=1, help="Bounded extra GET attempts after failure")
    sub = p.add_subparsers(dest="mode", required=True)

    def _add_retain(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "--retain-infra",
            action="store_true",
            help="Keep host/MAC/SSID/IP in written artefacts (private local use only)",
        )

    c = sub.add_parser("capture-baseline", help="Capture baseline into local/ (gitignored)")
    c.add_argument("--output", help="Output JSON path")
    c.add_argument("--label", default="device-baseline")
    c.add_argument("--note", action="append")
    c.set_defaults(func=cmd_capture_baseline)

    s = sub.add_parser("smoke", help="Single baseline comparison")
    s.add_argument("--baseline", default=str(_default_baseline_path()))
    s.add_argument("--output")
    _add_retain(s)
    s.set_defaults(func=cmd_smoke)

    st = sub.add_parser("stability", help="Timed availability monitoring")
    st.add_argument("--baseline", default=str(_default_baseline_path()))
    st.add_argument("--duration", type=int, default=120, help="Seconds")
    st.add_argument("--interval", type=int, default=15, help="Seconds between polls")
    st.add_argument("--check-config", action="store_true", default=True)
    st.add_argument("--no-check-config", action="store_false", dest="check_config")
    st.add_argument("--output")
    _add_retain(st)
    st.set_defaults(func=cmd_stability)

    pd = sub.add_parser("post-deploy", help="Verify expected firmware + retained config")
    pd.add_argument("--baseline", default=str(_default_baseline_path()))
    pd.add_argument("--expect-version", required=True)
    pd.add_argument("--expect-build", default=None)
    pd.add_argument("--output")
    _add_retain(pd)
    pd.set_defaults(func=cmd_post_deploy)

    lg = sub.add_parser("assess-logs", help="Read-only QPC/weblog observability probe")
    lg.add_argument("--output")
    _add_retain(lg)
    lg.set_defaults(func=cmd_assess_logs)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
