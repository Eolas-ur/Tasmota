"""Unit tests for the hardware regression harness (fixtures only; no live device)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest import mock

from eolasur_hw.compare import compare_against_baseline, compare_identity, validate_required_fields
from eolasur_hw.model import extract_identity, sanitize_report, sanitize_text
from eolasur_hw.monitor import RestartTracker

FIX = Path(__file__).resolve().parent / "fixtures"


def _load(name: str):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


class TestCompare(unittest.TestCase):
    def setUp(self):
        self.baseline = _load("example_baseline.json")
        self.status0 = _load("sample_status0.json")
        self.extras = self.baseline["extras_sanitised"]

    def test_smoke_match(self):
        ok, identity, findings = compare_against_baseline(self.baseline, self.status0, self.extras)
        self.assertTrue(ok, summarise := "\n".join(f"{f}" for f in findings if f["result"] == "fail"))
        self.assertEqual(identity["firmware"]["version"], "16.0.0.5(tasmota)")

    def test_missing_required_fields_fail(self):
        identity = extract_identity({"Status": {}}, {})
        findings = validate_required_fields(identity)
        self.assertTrue(any(f["result"] == "fail" for f in findings))
        ok, findings2 = compare_identity(self.baseline["identity"], identity)
        self.assertFalse(ok)

    def test_firmware_mismatch_fail(self):
        status = json.loads(json.dumps(self.status0))
        status["StatusFWR"]["Version"] = "99.0.0(other)"
        ok, _, findings = compare_against_baseline(self.baseline, status, self.extras)
        self.assertFalse(ok)
        self.assertTrue(any(f["path"] == "firmware.version" and f["result"] == "fail" for f in findings))

    def test_post_deploy_expected_version(self):
        ok, _, _ = compare_against_baseline(
            self.baseline,
            self.status0,
            self.extras,
            require_firmware=False,
            expected_version="16.0.0.5(tasmota)",
            expected_build="2026-11-18T17:07:44",
        )
        self.assertTrue(ok)
        ok2, _, _ = compare_against_baseline(
            self.baseline,
            self.status0,
            self.extras,
            require_firmware=False,
            expected_version="0.0.0",
        )
        self.assertFalse(ok2)


class TestRestartTracker(unittest.TestCase):
    def test_uptime_regression(self):
        t = RestartTracker()
        self.assertFalse(t.observe(1, 100))
        self.assertTrue(t.observe(1, 50))
        self.assertGreaterEqual(t.unexpected_restarts, 1)

    def test_boot_count_increase(self):
        t = RestartTracker()
        self.assertFalse(t.observe(10, 100))
        self.assertTrue(t.observe(11, 5))
        self.assertEqual(t.unexpected_restarts, 1)

    def test_stable(self):
        t = RestartTracker()
        self.assertFalse(t.observe(3, 10))
        self.assertFalse(t.observe(3, 20))
        self.assertFalse(t.observe(3, 30))
        self.assertEqual(t.unexpected_restarts, 0)


class TestSanitize(unittest.TestCase):
    def test_sanitize_text_ip_mac(self):
        text = "host 192.0.2.44 mac AA:BB:CC:DD:EE:FF ok"
        out = sanitize_text(text)
        self.assertNotIn("192.0.2.44", out)
        self.assertNotIn("AA:BB:CC:DD:EE:FF", out)

    def test_sanitize_report_redacts_infra(self):
        report = {
            "host": "192.0.2.10",
            "identity": {
                "network": {"ip_address": "192.0.2.10", "ssid": "SecretNet", "mac": "02:00:00:00:00:01"},
                "mqtt": {"host": "mqtt.example.test"},
            },
            "MqttUser": "should-go",
        }
        clean = sanitize_report(report)
        self.assertEqual(clean["host"], "<redacted>")
        self.assertEqual(clean["identity"]["network"]["ssid"], "<redacted>")
        self.assertEqual(clean["MqttUser"], "<redacted>")


class TestClientReadonly(unittest.TestCase):
    def test_get_rejects_relative_path(self):
        from eolasur_hw.client import TasmotaClient

        c = TasmotaClient(host="192.0.2.1")
        with self.assertRaises(ValueError):
            c.get("cm?cmnd=Status")

    def test_collect_status0_rejects_unknown(self):
        from eolasur_hw.client import TasmotaClient

        c = TasmotaClient(host="192.0.2.1")
        with mock.patch.object(c, "cmnd", return_value={"Command": "Unknown", "Input": "STATUS 0"}):
            with self.assertRaises(RuntimeError):
                c.collect_status0()

    def test_unreachable_raises(self):
        from eolasur_hw.client import TasmotaClient

        c = TasmotaClient(host="127.0.0.1", timeout=0.2, retries=0)
        with self.assertRaises(Exception):
            c.get("/cm?cmnd=Status%200")


if __name__ == "__main__":
    unittest.main()
