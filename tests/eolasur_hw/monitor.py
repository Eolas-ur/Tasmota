"""Stability helpers: uptime regression and unexpected restart detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class RestartTracker:
    first_boot: Optional[int] = None
    prev_uptime: Optional[int] = None
    unexpected_restarts: int = 0

    def observe(self, boot_count: Optional[int], uptime_sec: Optional[int]) -> bool:
        """
        Record one sample. Returns True if an unexpected restart is detected.

        Detection:
        - uptime_sec decreases versus previous sample
        - boot_count increases versus the first observed boot_count
        """
        restart = False
        if self.first_boot is None and boot_count is not None:
            self.first_boot = boot_count

        if self.prev_uptime is not None and uptime_sec is not None and uptime_sec < self.prev_uptime:
            restart = True
            self.unexpected_restarts += 1

        if (
            boot_count is not None
            and self.first_boot is not None
            and boot_count > self.first_boot
        ):
            restart = True
            self.unexpected_restarts = max(self.unexpected_restarts, boot_count - self.first_boot)

        if uptime_sec is not None:
            self.prev_uptime = uptime_sec
        return restart
