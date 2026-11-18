#!/usr/bin/env python3
"""Convenience launcher: python tests/eolasur_hw/run_harness.py ..."""

from __future__ import annotations

import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parents[1]
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from eolasur_hw.harness import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
