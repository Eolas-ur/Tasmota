#!/usr/bin/env python3
"""Offline source-level tests for M5-00D BearSSL server security overlay.

Runs without a device. Requires the pinned PlatformIO framework package
or an explicit path via HTTPS_FEASIBILITY_BSSL_SRC.
"""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from bearssl_server_secure_transform import (  # noqa: E402
    PINNED_SHA256,
    generate_overlay,
    sha256_file,
    transform,
)


def _framework_src() -> pathlib.Path:
    env = os.environ.get("HTTPS_FEASIBILITY_BSSL_SRC")
    if env:
        return pathlib.Path(env)
    home = pathlib.Path(os.environ.get("USERPROFILE") or os.environ.get("HOME") or "")
    candidate = (
        home
        / ".platformio"
        / "packages"
        / "framework-arduinoespressif8266"
        / "libraries"
        / "ESP8266WiFi"
        / "src"
        / "WiFiClientSecureBearSSL.cpp"
    )
    return candidate


class TestBearSSLServerOverlay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = _framework_src()
        if not cls.src.is_file():
            raise unittest.SkipTest(f"Pinned framework source not found: {cls.src}")

    def test_pinned_hash(self):
        self.assertEqual(sha256_file(self.src), PINNED_SHA256)

    def test_transform_enforces_tls12_and_aead_suite(self):
        text = self.src.read_text(encoding="utf-8")
        out = transform(text)
        self.assertIn("br_ssl_engine_set_versions(&cc->eng, BR_TLS12, BR_TLS12);", out)
        self.assertIn("suites_server_ec_secure_P", out)
        self.assertIn("BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", out)
        self.assertNotIn(
            "br_ssl_server_base_init(_sc_svr.get(), suites_server_ec_P,",
            out,
        )
        # Client path untouched
        self.assertIn("br_ssl_engine_set_versions(&cc->eng, BR_TLS10, BR_TLS12);", out)

    def test_secure_server_init_omits_weak_primitives(self):
        out = transform(self.src.read_text(encoding="utf-8"))
        start = out.index("M5-00D HTTPS feasibility overlay")
        # Function ends at matching close — use next occurrence of "\n  }\n\n}" pattern vicinity
        end = out.index("\n  }", start)
        server_fn = out[start:end]
        for banned in (
            "BR_TLS10",
            "br_tls10_prf",
            "set_default_aes_cbc",
            "set_default_des_cbc",
            "set_default_aes_ccm",
            "set_default_chapol",
        ):
            self.assertNotIn(banned, server_fn)

    def test_generate_overlay_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "WiFiClientSecureBearSSL.cpp"
            generate_overlay(self.src, dest)
            body = dest.read_text(encoding="utf-8")
            self.assertTrue(body.startswith("/*\n * M5-00D GENERATED OVERLAY"))
            self.assertIn("TLS 1.2 only", body)
            self.assertIn("suites_server_ec_secure_P", body)


if __name__ == "__main__":
    unittest.main()
