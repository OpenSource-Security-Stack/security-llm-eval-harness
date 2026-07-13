#!/usr/bin/env python3
"""Run a benchmark task against the model roster (spends API $).

Usage:
  python3 scripts/run.py --task cti --n 30
  python3 scripts/run.py --task malware --n 30 --models gpt-5.1 qwen3-235b
  python3 scripts/run.py --list
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness import config, runner  # noqa: E402
from harness.models import DEFAULT_MODELS, ROSTER, load_prices  # noqa: E402
import benchmarks  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", help="task id, e.g. cti / malware")
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--models", nargs="*", default=DEFAULT_MODELS)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--list", action="store_true", help="list registered tasks and exit")
    args = ap.parse_args()

    if args.list or not args.task:
        for t in benchmarks.all_tasks():
            mode = "run+import" if t.runnable() and t.load_results else \
                   ("run" if t.runnable() else "import-only")
            print(f"  {t.id:<12} {t.name:<28} {t.suite}  [{mode}]")
        return

    for mk in args.models:
        if mk not in ROSTER:
            sys.exit(f"unknown model '{mk}'. known: {list(ROSTER)}")
    task = benchmarks.get(args.task)
    if not task.runnable():
        sys.exit(f"task '{task.id}' is import-only (no run pipeline)")

    env = config.load_env()
    if env is None:
        print("warn: no .env found — API calls will fail without keys in the environment")
    load_prices()
    runner.run(task, args.models, n=args.n, workers=args.workers)


if __name__ == "__main__":
    main()
