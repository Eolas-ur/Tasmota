"""Snapshot extraction and secret / infrastructure sanitisation."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


REDACT_KEYS = {
    "password",
    "Password",
    "WebPassword",
    "MqttPassword",
    "MqttUser",
    "mqtt_pwd",
    "mqtt_user",
    "WifiPassword",
    "APPassword",
    "Password1",
    "Password2",
}

# Infrastructure identifiers redacted from published / default report artefacts.
INFRA_KEYS = {
    "ip_address",
    "IPAddress",
    "gateway",
    "Gateway",
    "dns1",
    "dns2",
    "DNSServer1",
    "DNSServer2",
    "mac",
    "Mac",
    "ssid",
    "SSId",
    "bssid",
    "BSSId",
    "hostname",
    "Hostname",
    "host",
    "MqttHost",
    "source_host",
    "Subnetmask",
    "subnetmask",
}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")


def _walk_redact(obj: Any, extra_keys: Optional[Set[str]] = None) -> Any:
    keys = set(REDACT_KEYS)
    if extra_keys:
        keys |= extra_keys
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in keys or "password" in str(k).lower():
                out[k] = "<redacted>"
            elif k in INFRA_KEYS:
                out[k] = "<redacted>"
            else:
                out[k] = _walk_redact(v, extra_keys)
        return out
    if isinstance(obj, list):
        return [_walk_redact(x, extra_keys) for x in obj]
    if isinstance(obj, str):
        text = _IPV4_RE.sub("<ip>", obj)
        text = _MAC_RE.sub("<mac>", text)
        return text
    return obj


def sanitize_text(text: str) -> str:
    """Redact IPv4 and MAC patterns from free-form log text."""
    text = _IPV4_RE.sub("<ip>", text)
    text = _MAC_RE.sub("<mac>", text)
    return text


def sanitize_report(obj: Any) -> Any:
    """Deep-sanitise a result object for safer local artefacts / sharing."""
    return _walk_redact(obj)


def extract_identity(status0: Dict[str, Any], extras: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Flatten stable identity fields used for regression comparison."""
    extras = extras or {}
    st = status0.get("Status") or {}
    prm = status0.get("StatusPRM") or {}
    fwr = status0.get("StatusFWR") or {}
    log = status0.get("StatusLOG") or {}
    mem = status0.get("StatusMEM") or {}
    net = status0.get("StatusNET") or {}
    mqt = status0.get("StatusMQT") or {}
    sts = status0.get("StatusSTS") or {}

    template = extras.get("Template") if isinstance(extras.get("Template"), dict) else {}
    module = extras.get("Module") if isinstance(extras.get("Module"), dict) else {}
    so65 = extras.get("SetOption65") if isinstance(extras.get("SetOption65"), dict) else {}
    wifi = sts.get("Wifi") or {}
    ssid_list = log.get("SSId") or []

    return {
        "firmware": {
            "version": fwr.get("Version"),
            "build_datetime": fwr.get("BuildDateTime"),
            "core": fwr.get("Core"),
            "sdk": fwr.get("SDK"),
            "hardware": fwr.get("Hardware"),
            "boot": fwr.get("Boot"),
            "cpu_mhz": fwr.get("CpuFrequency"),
        },
        "device": {
            "device_name": st.get("DeviceName"),
            "friendly_name": st.get("FriendlyName"),
            "topic": st.get("Topic"),
            "hostname": net.get("Hostname"),
            "mac": net.get("Mac"),
            "module": module.get("Module", st.get("Module")),
            "template": {
                "NAME": template.get("NAME"),
                "ARCH": template.get("ARCH"),
                "GPIO": template.get("GPIO"),
                "FLAG": template.get("FLAG"),
                "BASE": template.get("BASE"),
            },
        },
        "network": {
            "ip_address": net.get("IPAddress"),
            "gateway": net.get("Gateway"),
            "subnetmask": net.get("Subnetmask"),
            "dns1": net.get("DNSServer1"),
            "dns2": net.get("DNSServer2"),
            "ssid_present": bool(ssid_list and ssid_list[0]),
            "wifi_config": net.get("WifiConfig"),
            "webserver": net.get("Webserver"),
            "http_api": net.get("HTTP_API"),
            "ssid": ssid_list[0] if ssid_list else None,
            "bssid": wifi.get("BSSId"),
        },
        "power": {
            "power": sts.get("POWER", st.get("Power")),
            "power_on_state": st.get("PowerOnState"),
        },
        "qpc": {
            "setoption65": so65.get("SetOption65"),
            "fast_power_cycle_disable": so65.get("SetOption65") == "ON",
        },
        "memory": {
            "program_size_kb": mem.get("ProgramSize"),
            "free_kb": mem.get("Free"),
            "heap_kb": mem.get("Heap") if mem.get("Heap") is not None else sts.get("Heap"),
            "program_flash_kb": mem.get("ProgramFlashSize"),
            "flash_size_kb": mem.get("FlashSize"),
            "flash_chip_id": mem.get("FlashChipId"),
            "flash_mode": mem.get("FlashMode"),
            "flash_mhz": mem.get("FlashFrequency"),
        },
        "runtime": {
            "uptime": prm.get("Uptime"),
            "uptime_sec": sts.get("UptimeSec"),
            "restart_reason": prm.get("RestartReason"),
            "boot_count": prm.get("BootCount"),
            "cfg_holder": prm.get("CfgHolder"),
            "save_count": prm.get("SaveCount"),
            "startup_utc": prm.get("StartupUTC"),
            "ota_url": prm.get("OtaUrl"),
        },
        "mqtt": {
            "host": mqt.get("MqttHost"),
            "port": mqt.get("MqttPort"),
            "client": mqt.get("MqttClient"),
            "client_mask": mqt.get("MqttClientMask"),
            "connected_count": mqt.get("MqttCount"),
            "tls": mqt.get("MqttTLS"),
        },
        "logging": {
            "weblog": log.get("WebLog"),
            "seriallog": log.get("SerialLog"),
            "mqttlog": log.get("MqttLog"),
            "syslog": log.get("SysLog"),
        },
    }


# Required identity fields: missing/None => fail (no false PASS).
REQUIRED_IDENTITY_PATHS = [
    "firmware.version",
    "firmware.build_datetime",
    "firmware.hardware",
    "memory.program_size_kb",
    "memory.program_flash_kb",
    "memory.flash_size_kb",
    "runtime.cfg_holder",
    "power.power_on_state",
]


def build_baseline(
    host: str,
    status0: Dict[str, Any],
    extras: Dict[str, Any],
    *,
    label: str,
    notes: Optional[List[str]] = None,
    retain_infra: bool = True,
) -> Dict[str, Any]:
    """
    Build a baseline document.

    retain_infra=True keeps local-only identifiers (for private storage).
    Published fixtures should be authored synthetically or with retain_infra=False.
    """
    identity = extract_identity(status0, extras)
    raw_extras = {
        k: v
        for k, v in extras.items()
        if k
        in (
            "Module",
            "Template",
            "SetOption65",
            "DeviceName",
            "Hostname",
            "PowerOnState",
            "POWER",
            "OtaUrl",
        )
    }
    if retain_infra:
        host_out = host
        raw_status = _redact_secrets_only(status0)
        raw_extras = _redact_secrets_only(raw_extras)
    else:
        host_out = "<redacted>"
        identity = _walk_redact(identity)
        raw_status = _walk_redact(status0)
        raw_extras = _walk_redact(raw_extras)

    return {
        "schema": "eolasur-tasmota-hw-baseline/v1",
        "label": label,
        "captured_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_host": host_out,
        "notes": notes
        or [
            "Hardware baseline; passwords never retained.",
        ],
        "identity": identity,
        "status0_sanitised": raw_status,
        "extras_sanitised": raw_extras,
    }


def _redact_secrets_only(obj: Any) -> Any:
    """Redact credential keys only; keep infrastructure for private local baselines."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in REDACT_KEYS or "password" in str(k).lower():
                out[k] = "<redacted>"
            else:
                out[k] = _redact_secrets_only(v)
        return out
    if isinstance(obj, list):
        return [_redact_secrets_only(x) for x in obj]
    return obj


# Fields compared for smoke / config retention (path under identity).
COMPARE_PATHS = [
    ("firmware.version", True),
    ("firmware.build_datetime", True),
    ("firmware.hardware", True),
    ("firmware.core", True),
    ("device.device_name", True),
    ("device.hostname", True),
    ("device.mac", True),
    ("device.template.NAME", True),
    ("device.template.GPIO", True),
    ("device.template.BASE", True),
    ("network.ssid", False),
    ("power.power_on_state", True),
    ("power.power", True),
    ("qpc.setoption65", True),
    ("memory.program_size_kb", True),
    ("memory.program_flash_kb", True),
    ("memory.flash_size_kb", True),
    ("memory.flash_chip_id", True),
    ("memory.flash_mode", True),
    ("runtime.cfg_holder", True),
    ("runtime.ota_url", True),
    ("mqtt.host", True),
    ("mqtt.port", True),
    ("mqtt.client", True),
]


def dig(data: Dict[str, Any], dotted: str) -> Any:
    cur: Any = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur
