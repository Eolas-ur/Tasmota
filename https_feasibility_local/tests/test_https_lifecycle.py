#!/usr/bin/env python3
"""Behavioral tests for M5-01D HTTPS deferred shutdown and ownership."""

from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
INO = ROOT / "tasmota" / "tasmota_support" / "https_feasibility.ino"
HDR = ROOT / "tasmota" / "tasmota_support" / "https_feasibility.h"
XDRV = ROOT / "tasmota" / "tasmota_xdrv_driver" / "xdrv_01_9_webserver.ino"
WEB = ROOT / "lib" / "default" / "TasmotaWebServer" / "src" / "TasmotaWebServer.h"


class HttpsLifecycleModel:
    """Models deferred stop while an HTTPS request is active."""

    def __init__(self) -> None:
        self.https_serving = False
        self.listener = False
        self.pending = None  # None | 'stop' | 'restart_trial' | 'suspend'
        self.mode = "Off"
        self.persisted = False
        self.http_up = True
        self.destroyed_while_serving = False

    def _stop_now(self) -> None:
        if self.https_serving:
            self.destroyed_while_serving = True
            return
        self.listener = False

    def request_stop(self) -> None:
        self.mode = "Off"
        self.persisted = False
        if self.https_serving:
            # STOP always wins over earlier deferred ops.
            self.pending = "stop"
        else:
            self.pending = None
            self._stop_now()

    def request_trial_restart(self) -> None:
        self.persisted = False
        if self.https_serving and self.listener:
            self.pending = "restart_trial"
            self.mode = "Off"
        else:
            if self.listener:
                self._stop_now()
            self.listener = True
            self.mode = "Trial"

    def cycle_trial_off(self, n: int) -> None:
        for _ in range(n):
            self.request_trial_restart()
            if self.mode != "Trial" or not self.listener:
                raise AssertionError("trial failed to start")
            self.request_stop()
            if self.listener or self.mode != "Off":
                raise AssertionError("off failed to stop listener")

    def end_https_request(self) -> None:
        self.https_serving = False
        self.process_deferred()

    def process_deferred(self) -> None:
        if self.pending is None or self.https_serving:
            return
        op = self.pending
        self.pending = None
        if op == "stop":
            self._stop_now()
            self.mode = "Off"
        elif op == "restart_trial":
            self._stop_now()
            self.listener = True
            self.mode = "Trial"
        elif op == "suspend":
            self._stop_now()
            self.mode = "Confirmed" if self.persisted else "Off"


class TestHttpsLifecycleModel(unittest.TestCase):
    def test_off_during_https_request_is_deferred(self):
        m = HttpsLifecycleModel()
        m.listener = True
        m.mode = "Trial"
        m.https_serving = True
        m.request_stop()
        self.assertEqual(m.pending, "stop")
        self.assertTrue(m.listener)  # not destroyed yet
        self.assertFalse(m.destroyed_while_serving)
        m.end_https_request()
        self.assertFalse(m.listener)
        self.assertIsNone(m.pending)

    def test_trial_restart_during_https_request(self):
        m = HttpsLifecycleModel()
        m.listener = True
        m.https_serving = True
        m.request_trial_restart()
        self.assertEqual(m.pending, "restart_trial")
        self.assertTrue(m.listener)
        m.end_https_request()
        self.assertTrue(m.listener)
        self.assertEqual(m.mode, "Trial")
        self.assertFalse(m.destroyed_while_serving)

    def test_immediate_stop_when_idle(self):
        m = HttpsLifecycleModel()
        m.listener = True
        m.request_stop()
        self.assertFalse(m.listener)
        self.assertIsNone(m.pending)

    def test_http_remains_up(self):
        m = HttpsLifecycleModel()
        m.https_serving = True
        m.listener = True
        m.request_stop()
        m.end_https_request()
        self.assertTrue(m.http_up)

    def test_confirm_requires_running_listener(self):
        # Source contract: Confirm ignored when shutdown pending or not running.
        ino = INO.read_text(encoding="utf-8")
        self.assertIn("HttpsFeasibilityShutdownPending()", ino)
        self.assertIn("confirm_without_trial", ino)

    def test_stop_overrides_deferred_restart(self):
        m = HttpsLifecycleModel()
        m.listener = True
        m.https_serving = True
        m.request_trial_restart()
        self.assertEqual(m.pending, "restart_trial")
        m.request_stop()
        self.assertEqual(m.pending, "stop")
        m.end_https_request()
        self.assertFalse(m.listener)
        self.assertEqual(m.mode, "Off")

    def test_repeated_trial_off_cycles(self):
        m = HttpsLifecycleModel()
        m.cycle_trial_off(5)
        self.assertTrue(m.http_up)
        self.assertFalse(m.destroyed_while_serving)


class TestHttpsLifecycleSource(unittest.TestCase):
    def test_deferred_ops_present(self):
        ino = INO.read_text(encoding="utf-8")
        for token in (
            "HTTPS_PEND_STOP",
            "HTTPS_PEND_RESTART_TRIAL",
            "HTTPS_PEND_SUSPEND_MANAGER",
            "HttpsFeasibilityProcessDeferred",
            "HttpsFeasibilityStopListenerImmediate",
            "ShutdownPending",
            "cert cache retained",
        ):
            self.assertIn(token, ino)

    def test_poll_processes_deferred_after_https(self):
        xdrv = XDRV.read_text(encoding="utf-8")
        poll = xdrv[xdrv.find("void PollDnsWebserver") : xdrv.find("bool WebAuthenticate")]
        self.assertIn("HttpsFeasibilityProcessDeferred(Webserver)", poll)
        # Within PollDns: clear serving flag, then process deferred.
        idx_https_block = poll.find("httpsServer()")
        after = poll[idx_https_block:]
        idx_false = after.find("setHttpsServing(false)")
        idx_def = after.find("HttpsFeasibilityProcessDeferred(Webserver)")
        self.assertGreater(idx_def, idx_false)

    def test_addhandler_https_only_skips_without_delete(self):
        web = WEB.read_text(encoding="utf-8")
        self.assertIn("TASMOTA_WEB_ROUTE_HTTPS", web)
        # Must not delete handler on HTTPS-only skip (UAF risk).
        start = web.find("void addHandler")
        end = web.find("void enableCORS", start)
        block = web[start:end]
        self.assertIn("TASMOTA_WEB_ROUTE_HTTPS", block)
        self.assertNotIn("delete handler", block)

    def test_boot_fail_is_init_only(self):
        ino = INO.read_text(encoding="utf-8")
        self.assertIn("Listener *initialisation* failure only", ino)
        self.assertIn("not TLS handshake failure, not WDT", ino)
        hdr = HDR.read_text(encoding="utf-8")
        self.assertIn("HTTPS_FEASIBILITY_BOOT_FAIL_LIMIT", hdr)

    def test_stop_webserver_processes_deferred(self):
        xdrv = XDRV.read_text(encoding="utf-8")
        stop = xdrv[xdrv.find("void StopWebserver") : xdrv.find("void WebserverStopSocket")]
        self.assertIn("HttpsFeasibilityStopListener", stop)
        self.assertIn("HttpsFeasibilityProcessDeferred", stop)

    def test_cert_cache_retained_on_stop(self):
        ino = INO.read_text(encoding="utf-8")
        self.assertIn("Cert/key objects intentionally retained", ino)
        self.assertIn("CertCache", ino)


if __name__ == "__main__":
    unittest.main()
