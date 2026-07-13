#!/usr/bin/env python3
"""Rebuild rankings.json + rankings.js from cached results (no API spend).

Usage:
  python3 scripts/export.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness import config, export  # noqa: E402
from harness.models import load_prices  # noqa: E402
import benchmarks  # noqa: E402


def main():
    config.load_env()      # only needed for price fallback on records missing cost_usd
    load_prices()
    export.export(benchmarks.all_tasks())


if __name__ == "__main__":
    main()
