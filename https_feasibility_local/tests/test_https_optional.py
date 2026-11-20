#!/usr/bin/env python3
"""Offline tests for M5-01A optional HTTPS / experimental safeguards."""

from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
INO = ROOT / "tasmota" / "tasmota_support" / "https_feasibility.ino"
HDR = ROOT / "tasmota" / "tasmota_support" / "https_feasibility.h"
XDRV = ROOT / "tasmota" / "tasmota_xdrv_driver" / "xdrv_01_9_webserver.ino"
TYPES = ROOT / "tasmota" / "include" / "tasmota_types.h"
WEB = ROOT / "lib" / "default" / "TasmotaWebServer" / "src" / "TasmotaWebServer.h"


class TestHttpsOptional(unittest.TestCase):
    def test_default_disabled_persistence_bit(self):
        types = TYPES.read_text(encoding="utf-8")
        self.assertIn("https_webserver", types)
        self.assertIn("CMND_HTTPSWEB", types)

    def test_http_not_replaced_by_tls_port(self):
        xdrv = XDRV.read_text(encoding="utf-8")
        self.assertNotIn("HTTPS_FEASIBILITY_PORT);", xdrv.split("StartWebserver")[1].split("StopWebserver")[0])
        self.assertIn("http_port", xdrv)
        self.assertIn("HttpsFeasibilityStartListener", xdrv)
        self.assertIn("setHttpsServing(false)", xdrv)
        web = WEB.read_text(encoding="utf-8")
        self.assertIn("TasmotaHttpWebServer", web)
        self.assertIn("attachHttps", web)

    def test_trial_confirm_off_commands(self):
        ino = INO.read_text(encoding="utf-8")
        self.assertIn('PSTR("Trial")', ino)
        self.assertIn('PSTR("Confirm")', ino)
        self.assertIn("HTTPS_MODE_TRIAL", ino)
        self.assertIn("HTTPS_MODE_CONFIRMED", ino)
        self.assertIn("HttpsTrialDeadlineMs", ino)
        self.assertIn("Settings->sbflag1.https_webserver = 0", ino)
        self.assertIn("Settings->sbflag1.https_webserver = 1", ino)
        self.assertIn("SettingsSave(0)", ino)

    def test_failed_https_leaves_http_note(self):
        ino = INO.read_text(encoding="utf-8")
        self.assertIn("HTTP unchanged", ino)
        xdrv = XDRV.read_text(encoding="utf-8")
        self.assertIn("HTTP continues", xdrv)

    def test_redirect_reserved_disabled(self):
        hdr = HDR.read_text(encoding="utf-8")
        self.assertIn("HttpRedirectToHttps", hdr)
        ino = INO.read_text(encoding="utf-8")
        self.assertIn('\\"HttpRedirectToHttps\\":0', ino)

    def test_facade_dual_listener(self):
        web = WEB.read_text(encoding="utf-8")
        self.assertIn("setHttpsServing", web)
        self.assertIn("TasmotaHttpsWebServer", web)
        self.assertIn("TasmotaHttpWebServer", web)


if __name__ == "__main__":
    unittest.main()
