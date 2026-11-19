#!/usr/bin/env python3
"""Offline tests for M5-00G HTTPS instrumentation semantics."""

from __future__ import annotations

import unittest


def classify_accept(connected: bool, err: int) -> str:
    """Mirror HttpsFeasibilityOnAcceptEnd classification."""
    if connected and err == 0:
        return "ok"
    if (not connected) and err != 0:
        return "fail"
    if (not connected) and err == 0:
        return "unknown"
    return "fail"  # connected but err != 0


class TestHttpsInstrumentation(unittest.TestCase):
    def test_success_once(self):
        self.assertEqual(classify_accept(True, 0), "ok")

    def test_fail_with_error(self):
        self.assertEqual(classify_accept(False, -1000), "fail")
        self.assertEqual(classify_accept(False, 42), "fail")

    def test_unknown_idle_or_cleared(self):
        self.assertEqual(classify_accept(False, 0), "unknown")

    def test_connected_with_error_is_fail(self):
        self.assertEqual(classify_accept(True, 5), "fail")

    def test_heap_labels_document_sampling(self):
        # Contract: JSON field names used by HttpsMetrics command.
        required = {
            "HeapMinSampled",
            "PeakIsSampled",
            "HeapAfterIobuf",
            "HeapAfterEngine",
            "HsOk",
            "HsFail",
            "HsUnknown",
        }
        # Sourced from https_feasibility.ino Response_P — keep in sync.
        payload_keys = {
            "HeapBeforeInit",
            "HeapAfterInit",
            "HeapBeforeAccept",
            "HeapAfterIobuf",
            "HeapAfterEngine",
            "HeapAfterHs",
            "HeapMinSampled",
            "HeapAfterDisc",
            "MaxBlockMin",
            "FragMax",
            "PeakIsSampled",
            "HsMs",
            "HsMaxMs",
            "HsOk",
            "HsFail",
            "HsUnknown",
            "HttpSeen",
            "LastSslErr",
            "Disconnects",
            "RxBuf",
            "TxBuf",
        }
        self.assertTrue(required.issubset(payload_keys))


if __name__ == "__main__":
    unittest.main()
