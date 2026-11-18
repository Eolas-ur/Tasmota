"""Minimal read-only HTTP client for Tasmota device APIs (GET only)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class RequestRecord:
    path: str
    ok: bool
    elapsed_ms: float
    status_code: Optional[int] = None
    error: Optional[str] = None
    bytes: int = 0


@dataclass
class TasmotaClient:
    host: str
    timeout: float = 12.0
    user: Optional[str] = None
    password: Optional[str] = None
    retries: int = 1  # bounded extra attempts after the first failure
    retry_delay_s: float = 0.5
    records: List[RequestRecord] = field(default_factory=list)

    @property
    def base(self) -> str:
        return f"http://{self.host}"

    def _auth_opener(self) -> urllib.request.OpenerDirector:
        if self.user is None:
            return urllib.request.build_opener()
        pwd = self.password or ""
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, self.base, self.user, pwd)
        return urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(mgr))

    def get(self, path: str, timeout: Optional[float] = None) -> Tuple[int, bytes, float]:
        """HTTP GET only. Never issues POST/PUT/DELETE."""
        if not path.startswith("/"):
            raise ValueError("path must be absolute (start with /)")
        url = self.base + path
        attempts = max(1, 1 + int(self.retries))
        last_exc: Optional[BaseException] = None
        for attempt in range(attempts):
            t0 = time.perf_counter()
            try:
                req = urllib.request.Request(url, method="GET")
                with self._auth_opener().open(req, timeout=timeout or self.timeout) as resp:
                    body = resp.read()
                    elapsed = (time.perf_counter() - t0) * 1000.0
                    self.records.append(
                        RequestRecord(
                            path=path,
                            ok=True,
                            elapsed_ms=elapsed,
                            status_code=getattr(resp, "status", 200),
                            bytes=len(body),
                        )
                    )
                    return getattr(resp, "status", 200), body, elapsed
            except Exception as exc:  # noqa: BLE001
                elapsed = (time.perf_counter() - t0) * 1000.0
                self.records.append(
                    RequestRecord(path=path, ok=False, elapsed_ms=elapsed, error=str(exc))
                )
                last_exc = exc
                if attempt + 1 < attempts:
                    time.sleep(self.retry_delay_s)
        assert last_exc is not None
        raise last_exc

    def cmnd(self, command: str) -> Dict[str, Any]:
        quoted = urllib.parse.quote(command, safe="")
        status, body, _ = self.get(f"/cm?cmnd={quoted}")
        if status != 200:
            raise RuntimeError(f"HTTP {status} for command {command!r}")
        text = body.decode("utf-8", "replace").strip()
        if not text:
            raise RuntimeError(f"Empty response for {command!r}")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Non-JSON response for {command!r}: {text[:200]}") from exc
        if not isinstance(data, dict):
            raise RuntimeError(f"Expected JSON object for {command!r}")
        return data

    def console_tail(self) -> str:
        """Fetch weblog buffer via console refresh endpoint (read-only GET)."""
        try:
            status, body, _ = self.get("/cs?c2=0")
            if status != 200:
                return ""
            return body.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return ""

    def collect_status0(self) -> Dict[str, Any]:
        data = self.cmnd("Status 0")
        # Minimal / broken images often return {"Command":"Unknown",...}
        if "StatusFWR" not in data and "Status" not in data:
            raise RuntimeError(
                f"Status 0 missing required sections (got keys {sorted(data.keys())})"
            )
        return data

    def collect_extras(self) -> Dict[str, Any]:
        extras: Dict[str, Any] = {}
        for cmd in (
            "Module",
            "Template",
            "SetOption65",
            "DeviceName",
            "Hostname",
            "PowerOnState",
            "POWER",
            "OtaUrl",
        ):
            try:
                extras[cmd] = self.cmnd(cmd)
            except Exception as exc:  # noqa: BLE001
                extras[cmd] = {"error": str(exc)}
        return extras
