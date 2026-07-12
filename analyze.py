#!/usr/bin/env python3
"""Analyze a CyberSOCEval results JSONL: headline, fair common-subset, reliability.

Usage: python3 analyze.py [results/malware_analysis_n30_*.jsonl]   (default: latest)
"""
import glob
import json
import sys
from collections import defaultdict

f = sys.argv[1] if len(sys.argv) > 1 else sorted(glob.glob("results/malware_analysis_n*.jsonl"))[-1]
rs = [json.loads(l) for l in open(f)]
models = sorted({r["model"] for r in rs})
by_model = {m: {r["sha256"] + r["question"] if "question" in r else r["sha256"]: r
               for r in rs if r["model"] == m} for m in models}

# question key = sha256 (unique per q in our subset selection is not guaranteed; use sha256+correct)
def qkey(r):
    return r["sha256"] + "".join(r["correct_options"])

by_model = defaultdict(dict)
for r in rs:
    by_model[r["model"]][qkey(r)] = r

all_q = set()
for m in models:
    all_q |= set(by_model[m])

# common subset = questions every model PARSED (parse_ok True)
common = [q for q in all_q if all(by_model[m].get(q, {}).get("parse_ok") for m in models)]

print(f"file: {f}")
print(f"models: {models}  |  questions: {len(all_q)}  |  parsed-by-all: {len(common)}\n")

print("HEADLINE (all questions; failures score 0)")
print(f"{'model':<14}{'exact%':>8}{'meanJac':>9}{'parse✓%':>9}{'lat(s)':>8}{'ctok/q':>8}")
print("-" * 56)
for m in models:
    rows = list(by_model[m].values())
    n = len(rows)
    exact = 100 * sum(r["answered_correctly"] == "true" for r in rows) / n
    mj = sum(r["score"] for r in rows) / n
    pok = 100 * sum(bool(r.get("parse_ok")) for r in rows) / n
    lat = sum(r["latency"] for r in rows) / n
    ctok = [r["completion_tokens"] for r in rows if r.get("completion_tokens")]
    ct = sum(ctok) / len(ctok) if ctok else 0
    print(f"{m:<14}{exact:>7.1f}%{mj:>9.3f}{pok:>8.0f}%{lat:>8.1f}{ct:>8.0f}")

print(f"\nFAIR — common subset parsed by ALL models (n={len(common)})")
print(f"{'model':<14}{'exact%':>8}{'meanJac':>9}")
print("-" * 31)
fair = []
for m in models:
    rows = [by_model[m][q] for q in common]
    n = len(rows) or 1
    exact = 100 * sum(r["answered_correctly"] == "true" for r in rows) / n
    mj = sum(r["score"] for r in rows) / n
    fair.append((m, exact, mj))
    print(f"{m:<14}{exact:>7.1f}%{mj:>9.3f}")

print("\nranking by fair meanJac:",
      " > ".join(m for m, _, _ in sorted(fair, key=lambda x: -x[2])))
