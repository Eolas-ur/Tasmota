#!/usr/bin/env python3
"""Generate non-production ECDSA P-256 cert/key material for HTTPS feasibility builds.

Outputs (gitignored):
  https_feasibility_local/certs/server.key.pem
  https_feasibility_local/certs/server.cert.pem
  https_feasibility_local/certs/https_feasibility_certs.h

Includes Subject Alternative Names for lab hostname testing:
  DNS: CN, localhost; IP: 127.0.0.1

Trust: self-signed only — browsers require an explicit exception; not a public CA.

Requires OpenSSL on PATH (Git for Windows openssl.exe is fine).
Never commit the generated PEMs or the header containing the private key.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile


def _openssl() -> str:
    found = shutil.which("openssl")
    if found:
        return found
    git_openssl = pathlib.Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
    if git_openssl.is_file():
        return str(git_openssl)
    raise SystemExit("openssl not found on PATH")


def _c_string_literal(data: str) -> str:
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
    ap.add_argument(
        "--san-dns",
        action="append",
        default=None,
        help="Extra DNS SAN entries (CN and localhost always included)",
    )
    ap.add_argument(
        "--san-ip",
        action="append",
        default=None,
        help="IP SAN entries (127.0.0.1 always included)",
    )
    args = ap.parse_args()

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    key = out / "server.key.pem"
    cert = out / "server.cert.pem"
    header = out / "https_feasibility_certs.h"
    openssl = _openssl()

    dns_names = [args.cn, "localhost"]
    if args.san_dns:
        dns_names.extend(args.san_dns)
    # de-dupe preserving order
    seen = set()
    dns_names = [d for d in dns_names if not (d in seen or seen.add(d))]

    ip_names = ["127.0.0.1"]
    if args.san_ip:
        ip_names.extend(args.san_ip)
    seen = set()
    ip_names = [i for i in ip_names if not (i in seen or seen.add(i))]

    dns_lines = "\n".join(f"DNS.{idx} = {name}" for idx, name in enumerate(dns_names, start=1))
    ip_lines = "\n".join(f"IP.{idx} = {addr}" for idx, addr in enumerate(ip_names, start=1))

    conf = f"""[req]
distinguished_name = req_dn
x509_extensions = v3_req
prompt = no

[req_dn]
CN = {args.cn}
O = Tasmota HTTPS Feasibility
C = AU

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
{dns_lines}
{ip_lines}
"""

    with tempfile.TemporaryDirectory() as tmp:
        conf_path = pathlib.Path(tmp) / "san.cnf"
        conf_path.write_text(conf, encoding="utf-8", newline="\n")
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
                "-config",
                str(conf_path),
                "-extensions",
                "v3_req",
            ]
        )

    key_pem = key.read_text(encoding="utf-8")
    cert_pem = cert.read_text(encoding="utf-8")
    header.write_text(
        "/* Auto-generated non-production certs. DO NOT COMMIT.\n"
        " * Self-signed EC P-256 with SANs for lab hostname testing.\n"
        " * Not trusted by browsers without an explicit exception.\n"
        " */\n"
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
    print(f"SANs DNS={dns_names} IP={ip_names}")
    print("Remember: certs/ is gitignored — do not force-add these files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
