# PlatformIO extra_script for env:tasmota-https-feasibility.
# Generates a project-local WiFiClientSecureBearSSL.cpp overlay and redirects
# the ESP8266WiFi compile unit to it. Never modifies the global framework package.

Import("env")  # noqa: F821 — injected by PlatformIO/SCons

import pathlib
import sys

project_dir = pathlib.Path(env["PROJECT_DIR"])  # noqa: F821
scripts_dir = project_dir / "https_feasibility_local" / "scripts"
sys.path.insert(0, str(scripts_dir))

from bearssl_server_secure_transform import generate_overlay  # noqa: E402

try:
    fw_dir = pathlib.Path(env.PioPlatform().get_package_dir("framework-arduinoespressif8266"))  # noqa: F821
except Exception as exc:  # noqa: BLE001
    sys.stderr.write(f"bearssl_server_secure_overlay: cannot locate framework: {exc}\n")
    env.Exit(1)  # noqa: F821

src = fw_dir / "libraries" / "ESP8266WiFi" / "src" / "WiFiClientSecureBearSSL.cpp"
dest = project_dir / "https_feasibility_local" / "framework_overlay" / "WiFiClientSecureBearSSL.cpp"

try:
    generate_overlay(src, dest)
except Exception as exc:  # noqa: BLE001
    sys.stderr.write(f"bearssl_server_secure_overlay: {exc}\n")
    env.Exit(1)  # noqa: F821

print(f"HTTPS feasibility: BearSSL server overlay -> {dest}")
dest_str = str(dest)


def _replace_node(node):
    path = str(node).replace("\\", "/")
    if path.endswith("libraries/ESP8266WiFi/src/WiFiClientSecureBearSSL.cpp"):
        return env.File(dest_str)  # noqa: F821
    return node


env.AddBuildMiddleware(_replace_node)  # noqa: F821
