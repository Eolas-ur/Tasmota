"""Baseline comparison helpers."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .model import COMPARE_PATHS, REQUIRED_IDENTITY_PATHS, dig, extract_identity


def validate_required_fields(identity: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fail closed when required Status-derived fields are missing."""
    findings: List[Dict[str, Any]] = []
    for path in REQUIRED_IDENTITY_PATHS:
        got = dig(identity, path)
        if got is None or got == "":
            findings.append(
                {
                    "path": path,
                    "result": "fail",
                    "expected": "<required>",
                    "actual": got,
                    "note": "required identity field missing",
                }
            )
    return findings


def compare_identity(
    baseline_identity: Dict[str, Any],
    current_identity: Dict[str, Any],
    *,
    require_firmware: bool = True,
    expected_version: Optional[str] = None,
    expected_build: Optional[str] = None,
) -> Tuple[bool, List[Dict[str, Any]]]:
    """Return (passed, findings). Findings include hard fails and warnings."""
    findings: List[Dict[str, Any]] = []
    hard_fail = False

    missing = validate_required_fields(current_identity)
    if missing:
        hard_fail = True
        findings.extend(missing)

    for path, required in COMPARE_PATHS:
        if path.startswith("firmware.") and not require_firmware:
            continue
        exp = dig(baseline_identity, path)
        got = dig(current_identity, path)
        if exp == got:
            findings.append({"path": path, "result": "match", "expected": exp, "actual": got})
            continue
        # Missing required actual already covered; still fail mismatch including None vs value
        severity = "fail" if required else "warn"
        if severity == "fail":
            hard_fail = True
        findings.append(
            {
                "path": path,
                "result": severity,
                "expected": exp,
                "actual": got,
            }
        )

    if expected_version is not None:
        got_v = dig(current_identity, "firmware.version")
        if got_v != expected_version:
            hard_fail = True
            findings.append(
                {
                    "path": "firmware.version",
                    "result": "fail",
                    "expected": expected_version,
                    "actual": got_v,
                    "note": "post-deploy expected version",
                }
            )
        else:
            findings.append(
                {
                    "path": "firmware.version",
                    "result": "match",
                    "expected": expected_version,
                    "actual": got_v,
                    "note": "post-deploy expected version",
                }
            )

    if expected_build is not None:
        got_b = dig(current_identity, "firmware.build_datetime")
        if got_b != expected_build:
            hard_fail = True
            findings.append(
                {
                    "path": "firmware.build_datetime",
                    "result": "fail",
                    "expected": expected_build,
                    "actual": got_b,
                    "note": "post-deploy expected build",
                }
            )
        else:
            findings.append(
                {
                    "path": "firmware.build_datetime",
                    "result": "match",
                    "expected": expected_build,
                    "actual": got_b,
                    "note": "post-deploy expected build",
                }
            )

    return (not hard_fail), findings


def compare_against_baseline(
    baseline: Dict[str, Any],
    status0: Dict[str, Any],
    extras: Dict[str, Any],
    **kwargs: Any,
) -> Tuple[bool, Dict[str, Any], List[Dict[str, Any]]]:
    current = extract_identity(status0, extras)
    ok, findings = compare_identity(baseline.get("identity") or {}, current, **kwargs)
    return ok, current, findings


def summarise_findings(findings: List[Dict[str, Any]]) -> str:
    fails = [f for f in findings if f["result"] == "fail"]
    warns = [f for f in findings if f["result"] == "warn"]
    matches = [f for f in findings if f["result"] == "match"]
    lines = [
        f"matches={len(matches)} warnings={len(warns)} failures={len(fails)}",
    ]
    for f in fails:
        lines.append(f"FAIL {f['path']}: expected={f['expected']!r} actual={f['actual']!r}")
    for f in warns:
        lines.append(f"WARN {f['path']}: expected={f['expected']!r} actual={f['actual']!r}")
    return "\n".join(lines)
