#!/usr/bin/env python3
"""Generate non-production ECDSA P-256 cert/key material for HTTPS feasibility builds.

Outputs (gitignored):
  https_feasibility_local/certs/server.key.pem
  https_feasibility_local/certs/server.cert.pem
  https_feasibility_local/certs/https_feasibility_certs.h

Requires OpenSSL on PATH (Git for Windows openssl.exe is fine).
Never commit the generated PEMs or the header containing the private key.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys


def _openssl() -> str:
    found = shutil.which("openssl")
    if found:
        return found
    git_openssl = pathlib.Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
    if git_openssl.is_file():
        return str(git_openssl)
    raise SystemExit("openssl not found on PATH")


def _c_string_literal(data: str) -> str:
    # Keep as a readable multi-line C string for PROGMEM PEM embedding.
    lines = data.replace("\r\n", "\n").strip("\n").split("\n")
    parts = [f'  "{line}\\n"' for line in lines]
    return "\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--out-dir",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1] / "certs",
    )
    ap.add_argument("--days", type=int, default=3650)
    ap.add_argument("--cn", default="tasmota-https-feasibility.local")
    args = ap.parse_args()

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    key = out / "server.key.pem"
    cert = out / "server.cert.pem"
    header = out / "https_feasibility_certs.h"
    openssl = _openssl()

    subprocess.check_call(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            str(args.days),
            "-subj",
            f"/CN={args.cn}/O=Tasmota HTTPS Feasibility/C=AU",
        ]
    )

    key_pem = key.read_text(encoding="utf-8")
    cert_pem = cert.read_text(encoding="utf-8")
    header.write_text(
        "/* Auto-generated non-production certs. DO NOT COMMIT. */\n"
        "#pragma once\n"
        "#ifndef HTTPS_FEASIBILITY_CERTS_H\n"
        "#define HTTPS_FEASIBILITY_CERTS_H\n\n"
        "static const char HTTPS_FEASIBILITY_SERVER_CERT[] PROGMEM =\n"
        f"{_c_string_literal(cert_pem)};\n\n"
        "static const char HTTPS_FEASIBILITY_SERVER_KEY[] PROGMEM =\n"
        f"{_c_string_literal(key_pem)};\n\n"
        "#endif\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {key}")
    print(f"Wrote {cert}")
    print(f"Wrote {header}")
    print("Remember: certs/ is gitignored — do not force-add these files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
