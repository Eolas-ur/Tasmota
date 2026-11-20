#!/usr/bin/env python3
"""Offline tests for M5-00G/H HTTPS instrumentation semantics."""

from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
INO = ROOT / "tasmota" / "tasmota_support" / "https_feasibility.ino"
TRANSFORM = (
    ROOT
    / "https_feasibility_local"
    / "scripts"
    / "bearssl_server_secure_transform.py"
)


def classify_hs(hs_ok: int, transport_connected: bool = True) -> str:
    """Mirror HttpsFeasibilityOnAcceptEnd classification (M5-00H)."""
    del transport_connected
    if hs_ok == 1:
        return "ok"
    if hs_ok == 0:
        return "fail"
    return "unknown"


class TestHttpsInstrumentation(unittest.TestCase):
    def test_success_once(self):
        self.assertEqual(classify_hs(1, True), "ok")

    def test_success_then_immediate_disconnect(self):
        self.assertEqual(classify_hs(1, False), "ok")

    def test_fail_with_error(self):
        self.assertEqual(classify_hs(0, False), "fail")
        self.assertEqual(classify_hs(0, True), "fail")

    def test_unknown_without_attempt(self):
        self.assertEqual(classify_hs(-1, False), "unknown")
        self.assertEqual(classify_hs(-1, True), "unknown")

    def test_transport_does_not_override_failure(self):
        self.assertEqual(classify_hs(0, True), "fail")

    def test_heap_and_http_labels(self):
        required = {
            "HsOk",
            "HsFail",
            "HsUnknown",
            "HttpClientPolls",
            "TransportConnected",
            "HeapMinSampled",
            "PeakIsSampled",
        }
        ino = INO.read_text(encoding="utf-8")
        for key in required:
            self.assertIn(f'\\"{key}\\"', ino)
        self.assertIn("HttpsFeasibilityTlsHsOk", ino)
        self.assertIn("heap_ckpt_after_engine", ino)

    def test_overlay_feeds_same_classification(self):
        transform = TRANSFORM.read_text(encoding="utf-8")
        self.assertIn("bool hs_ok = _wait_for_handshake();", transform)
        self.assertIn("HttpsFeasibilityTlsHsOk = 1;", transform)
        self.assertIn("HttpsFeasibilityTlsHsOk = 0;", transform)
        ino = INO.read_text(encoding="utf-8")
        self.assertIn("const int8_t hs = HttpsFeasibilityTlsHsOk;", ino)
        self.assertNotIn("if (connected && (err == 0))", ino)
        self.assertIn("last_transport_connected = client.connected();", ino)


if __name__ == "__main__":
    unittest.main()
