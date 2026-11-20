#!/usr/bin/env python3
"""Behavioral offline model of M5-01B HTTPS activation / recovery transitions."""

from __future__ import annotations

import unittest


class HttpsState:
    """Mirrors firmware HttpsWeb state without requiring a device."""

    OFF = "Off"
    TRIAL = "Trial"
    CONFIRMED = "Confirmed"

    def __init__(self) -> None:
        self.mode = self.OFF
        self.listener = False
        self.persisted = False
        self.boot_fails = 0
        self.boot_fail_limit = 3
        self.http_up = True
        self.trial_remaining = 0

    def off(self) -> None:
        self.persisted = False
        self.mode = self.OFF
        self.listener = False
        self.trial_remaining = 0

    def trial(self, ok: bool = True) -> None:
        was = self.persisted
        self.persisted = False
        if self.listener:
            self.listener = False
        self.mode = self.OFF
        if not ok or not self.http_up:
            return
        self.listener = True
        self.mode = self.TRIAL
        self.trial_remaining = 300
        assert was is False or self.persisted is False

    def confirm(self) -> None:
        if not self.listener:
            return
        self.persisted = True
        self.mode = self.CONFIRMED
        self.trial_remaining = 0

    def tick_trial_expire(self) -> None:
        if self.mode == self.TRIAL:
            self.listener = False
            self.mode = self.OFF
            self.persisted = False
            self.trial_remaining = 0

    def restart(self) -> None:
        # Trial never restores; confirmed restores listener attempt.
        was_persisted = self.persisted
        self.listener = False
        self.mode = self.OFF
        self.trial_remaining = 0
        if was_persisted:
            self.boot_start_confirmed(ok=True)

    def boot_start_confirmed(self, ok: bool) -> None:
        if not self.persisted:
            return
        if ok:
            self.listener = True
            self.mode = self.CONFIRMED
            self.boot_fails = 0
        else:
            self.listener = False
            self.boot_fails += 1
            if self.boot_fails >= self.boot_fail_limit:
                self.persisted = False
                self.mode = self.OFF
                self.boot_fails = 0

    def manager(self) -> None:
        self.listener = False
        if self.persisted:
            self.mode = self.CONFIRMED
        else:
            self.mode = self.OFF

    def https_init_fail(self) -> None:
        # Failure isolates — HTTP remains.
        assert self.http_up
        self.listener = False


class TestHttpsStateMachine(unittest.TestCase):
    def test_http_only_default(self):
        s = HttpsState()
        self.assertEqual(s.mode, HttpsState.OFF)
        self.assertFalse(s.listener)
        self.assertFalse(s.persisted)
        self.assertTrue(s.http_up)

    def test_off_to_trial_to_confirm(self):
        s = HttpsState()
        s.trial()
        self.assertEqual(s.mode, HttpsState.TRIAL)
        self.assertTrue(s.listener)
        self.assertFalse(s.persisted)
        s.confirm()
        self.assertEqual(s.mode, HttpsState.CONFIRMED)
        self.assertTrue(s.persisted)

    def test_trial_expiry(self):
        s = HttpsState()
        s.trial()
        s.tick_trial_expire()
        self.assertEqual(s.mode, HttpsState.OFF)
        self.assertFalse(s.listener)
        self.assertFalse(s.persisted)

    def test_restart_during_trial_does_not_restore(self):
        s = HttpsState()
        s.trial()
        s.restart()
        self.assertFalse(s.listener)
        self.assertFalse(s.persisted)
        self.assertEqual(s.mode, HttpsState.OFF)

    def test_restart_after_confirmed_restores(self):
        s = HttpsState()
        s.trial()
        s.confirm()
        s.restart()
        self.assertTrue(s.listener)
        self.assertTrue(s.persisted)
        self.assertEqual(s.mode, HttpsState.CONFIRMED)

    def test_confirmed_to_trial_clears_persistence(self):
        s = HttpsState()
        s.trial()
        s.confirm()
        s.trial()
        self.assertEqual(s.mode, HttpsState.TRIAL)
        self.assertFalse(s.persisted)

    def test_confirmed_to_off(self):
        s = HttpsState()
        s.trial()
        s.confirm()
        s.off()
        self.assertEqual(s.mode, HttpsState.OFF)
        self.assertFalse(s.persisted)
        self.assertFalse(s.listener)

    def test_https_failure_leaves_http(self):
        s = HttpsState()
        s.https_init_fail()
        self.assertTrue(s.http_up)

    def test_manager_suspends_listener_keeps_confirm(self):
        s = HttpsState()
        s.trial()
        s.confirm()
        s.manager()
        self.assertFalse(s.listener)
        self.assertTrue(s.persisted)
        self.assertEqual(s.mode, HttpsState.CONFIRMED)

    def test_boot_fail_suppression(self):
        s = HttpsState()
        s.trial()
        s.confirm()
        for _ in range(3):
            s.boot_start_confirmed(ok=False)
        self.assertFalse(s.persisted)
        self.assertEqual(s.mode, HttpsState.OFF)


class TestClientFacadeContracts(unittest.TestCase):
    def test_facade_returns_client_reference(self):
        web = (
            __import__("pathlib").Path(__file__).resolve().parents[2]
            / "lib"
            / "default"
            / "TasmotaWebServer"
            / "src"
            / "TasmotaWebServer.h"
        ).read_text(encoding="utf-8")
        self.assertIn("WiFiClient &client(void)", web)
        self.assertIn("activeClient(void)", web)
        self.assertIn("clientSecureCopy", web)
        # Must not return WiFiClient by value in the HTTPS facade.
        self.assertNotIn("WiFiClient client(void)", web)
        self.assertIn("TASMOTA_WEB_ROUTE_HTTPS", web)

    def test_backup_uses_client_reference(self):
        xdrv = (
            __import__("pathlib").Path(__file__).resolve().parents[2]
            / "tasmota"
            / "tasmota_xdrv_driver"
            / "xdrv_01_9_webserver.ino"
        ).read_text(encoding="utf-8")
        # auto& (or WiFiClient&) — never a by-value temporary that slices BearSSL.
        self.assertRegex(xdrv, r"auto\s*&myClient\s*=\s*Webserver->client\(\)")
        self.assertNotIn("WiFiClient myClient = Webserver->client();", xdrv)


if __name__ == "__main__":
    unittest.main()
