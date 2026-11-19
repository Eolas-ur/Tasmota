# Pure transform helpers for M5-00D BearSSL server security overlay.
# No PlatformIO imports — safe for offline unit tests.
#
# Upstream WiFiClientSecureBearSSL.cpp is LGPL-2.1-or-later
# (Arduino-ESP8266 / Earle F. Philhower, III).

from __future__ import annotations

import hashlib
import pathlib

# Pinned framework-arduinoespressif8266 2.8.0 (tasmota/Arduino gcc153.zip)
PINNED_SHA256 = "45121da7574d8e87405d4d54689b43f0c8d7a0076374a32235f33b6e685bac82"

SERVER_BASE_INIT_OLD = """  // Default initializion for our SSL clients
  static void br_ssl_server_base_init(br_ssl_server_context *cc, const uint16_t *cipher_list, int cipher_cnt) {
    uint16_t suites[cipher_cnt];
    memcpy_P(suites, cipher_list, cipher_cnt * sizeof(cipher_list[0]));
    br_ssl_server_zero(cc);
    br_ssl_engine_add_flags(&cc->eng, BR_OPT_NO_RENEGOTIATION);  // forbid SSL renegociation, as we free the Private Key after handshake
    br_ssl_engine_set_versions(&cc->eng, BR_TLS10, BR_TLS12);
    br_ssl_engine_set_suites(&cc->eng, suites, (sizeof suites) / (sizeof suites[0]));
#ifndef BEARSSL_SSL_BASIC
    br_ssl_engine_set_default_ec(&cc->eng);
#endif

    br_ssl_client_install_hashes(&cc->eng);
    br_ssl_engine_set_prf10(&cc->eng, &br_tls10_prf);
    br_ssl_engine_set_prf_sha256(&cc->eng, &br_tls12_sha256_prf);
    br_ssl_engine_set_prf_sha384(&cc->eng, &br_tls12_sha384_prf);
    br_ssl_engine_set_default_aes_cbc(&cc->eng);
#ifndef BEARSSL_SSL_BASIC
    br_ssl_engine_set_default_aes_ccm(&cc->eng);
    br_ssl_engine_set_default_aes_gcm(&cc->eng);
    br_ssl_engine_set_default_des_cbc(&cc->eng);
    br_ssl_engine_set_default_chapol(&cc->eng);
#endif
  }"""

SERVER_BASE_INIT_NEW = """  // M5-00D HTTPS feasibility overlay: TLS 1.2 only; register AEAD primitives only.
  // (Original Arduino-ESP8266 server init allowed TLS 1.0-1.2 and installed CBC/3DES.)
  static void br_ssl_server_base_init(br_ssl_server_context *cc, const uint16_t *cipher_list, int cipher_cnt) {
    uint16_t suites[cipher_cnt];
    memcpy_P(suites, cipher_list, cipher_cnt * sizeof(cipher_list[0]));
    br_ssl_server_zero(cc);
    br_ssl_engine_add_flags(&cc->eng, BR_OPT_NO_RENEGOTIATION);  // forbid SSL renegociation, as we free the Private Key after handshake
    br_ssl_engine_set_versions(&cc->eng, BR_TLS12, BR_TLS12);
    br_ssl_engine_set_suites(&cc->eng, suites, (sizeof suites) / (sizeof suites[0]));
#ifndef BEARSSL_SSL_BASIC
    br_ssl_engine_set_default_ec(&cc->eng);
#endif

    br_ssl_client_install_hashes(&cc->eng);
    br_ssl_engine_set_prf_sha256(&cc->eng, &br_tls12_sha256_prf);
#ifndef BEARSSL_SSL_BASIC
    br_ssl_engine_set_default_aes_gcm(&cc->eng);
#endif
  }"""

EC_INIT_OLD = """  br_ssl_server_base_init(_sc_svr.get(), suites_server_ec_P, sizeof(suites_server_ec_P) / sizeof(suites_server_ec_P[0]));
  br_ssl_server_set_single_ec(_sc_svr.get(), chain ? chain->getX509Certs() : nullptr, chain ? chain->getCount() : 0,
                               sk ? sk->getEC() : nullptr, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
                               cert_issuer_key_type, br_ssl_engine_get_ec(_eng), br_ecdsa_i15_sign_asn1);"""

EC_INIT_NEW = """  // M5-00D: ECDHE-ECDSA AES-128-GCM only (no CBC/3DES/static-ECDH from suites_server_ec_P).
  static const uint16_t suites_server_ec_secure_P[] PROGMEM = {
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  };
  br_ssl_server_base_init(_sc_svr.get(), suites_server_ec_secure_P, sizeof(suites_server_ec_secure_P) / sizeof(suites_server_ec_secure_P[0]));
  br_ssl_server_set_single_ec(_sc_svr.get(), chain ? chain->getX509Certs() : nullptr, chain ? chain->getCount() : 0,
                               sk ? sk->getEC() : nullptr, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
                               cert_issuer_key_type, br_ssl_engine_get_ec(_eng), br_ecdsa_i15_sign_asn1);"""

OVERLAY_BANNER = """/*
 * M5-00D GENERATED OVERLAY — do not edit by hand.
 * Source: framework-arduinoespressif8266 2.8.0 WiFiClientSecureBearSSL.cpp
 * Expected SHA256: {sha}
 * Policy: TLS 1.2 only; server EC suite ECDHE-ECDSA-AES128-GCM-SHA256 only.
 * Wired only into env:tasmota-https-feasibility via bearssl_server_secure_overlay.py
 * License: LGPL-2.1-or-later (original Arduino-ESP8266 / Earle F. Philhower, III)
 */
"""


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def transform(source: str) -> str:
    if SERVER_BASE_INIT_OLD not in source:
        raise RuntimeError("Pinned WiFiClientSecureBearSSL.cpp: server base init block not found")
    if EC_INIT_OLD not in source:
        raise RuntimeError("Pinned WiFiClientSecureBearSSL.cpp: EC server init block not found")
    if source.count(SERVER_BASE_INIT_OLD) != 1:
        raise RuntimeError("Pinned WiFiClientSecureBearSSL.cpp: unexpected duplicate server base init")
    if source.count(EC_INIT_OLD) != 1:
        raise RuntimeError("Pinned WiFiClientSecureBearSSL.cpp: unexpected duplicate EC server init")

    out = source.replace(SERVER_BASE_INIT_OLD, SERVER_BASE_INIT_NEW, 1)
    out = out.replace(EC_INIT_OLD, EC_INIT_NEW, 1)

    if "br_ssl_engine_set_versions(&cc->eng, BR_TLS10, BR_TLS12);" not in out:
        raise RuntimeError("Client TLS version line missing after transform — aborting")
    if "br_ssl_engine_set_versions(&cc->eng, BR_TLS12, BR_TLS12);" not in out:
        raise RuntimeError("Server TLS 1.2-only line missing after transform — aborting")
    if "suites_server_ec_secure_P" not in out:
        raise RuntimeError("Secure EC suite table missing after transform — aborting")
    if "br_ssl_server_base_init(_sc_svr.get(), suites_server_ec_P," in out:
        raise RuntimeError("Unrestricted suites_server_ec_P still used for EC server path")

    # Server base init must not mention weak protocol/primitive installs.
    start = out.index("M5-00D HTTPS feasibility overlay")
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
        if banned in server_fn:
            raise RuntimeError(f"Banned token '{banned}' remains in secure server base init")
    return out


def generate_overlay(framework_cpp: pathlib.Path, dest_cpp: pathlib.Path) -> pathlib.Path:
    digest = sha256_file(framework_cpp)
    if digest != PINNED_SHA256:
        raise RuntimeError(
            f"Framework WiFiClientSecureBearSSL.cpp SHA256 mismatch.\n"
            f"  expected: {PINNED_SHA256}\n"
            f"  actual:   {digest}\n"
            f"Refusing to patch an unexpected core revision."
        )
    text = framework_cpp.read_text(encoding="utf-8", errors="strict")
    patched = OVERLAY_BANNER.format(sha=digest) + transform(text)
    dest_cpp.parent.mkdir(parents=True, exist_ok=True)
    dest_cpp.write_text(patched, encoding="utf-8", newline="\n")
    return dest_cpp
