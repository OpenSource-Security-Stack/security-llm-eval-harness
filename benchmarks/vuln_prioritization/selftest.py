"""No-API self-test for the vuln_prio benchmark. Run from repo root:
    python3 benchmarks/vuln_prioritization/selftest.py
Exercises load/prompt/parse/score end-to-end and checks nDCG behaviour on a
perfect, a reversed, and a refusal ranking. Prints PASS/FAIL per check.
"""
import sys

from benchmarks.vuln_prioritization import bench

fails = 0


def check(name, ok):
    global fails
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        fails += 1


# (a) load
qs = bench.load()
print(f"\nloaded {len(qs)} questions "
      f"({len(qs[0]['cves'])} CVEs in q0)\n")
check("load returns questions", len(qs) >= 1)

# (b) one full prompt
item = qs[0]
print("=" * 70)
print("EXAMPLE PROMPT (q0):")
print("=" * 70)
print(bench.prompt(item))
print("=" * 70 + "\n")

g = bench.gold(item)

# (c) PERFECT ranking -> nDCG ≈ 1.0
perfect = sorted(g, key=lambda c: g[c], reverse=True)
s_perfect = bench.score(perfect, g)["ndcg"]
print(f"perfect ranking nDCG = {s_perfect:.4f}")
check("perfect ranking nDCG ≈ 1.0", abs(s_perfect - 1.0) < 1e-9)

# parse round-trips through the model-facing format
raw = "\n".join(f"{i+1}. {c}" for i, c in enumerate(perfect))
check("parse recovers the perfect order", bench.parse(raw) == perfect)

# (d) REVERSED / bad ranking -> much lower
worst = sorted(g, key=lambda c: g[c])          # least-urgent first
s_worst = bench.score(worst, g)["ndcg"]
print(f"reversed ranking nDCG = {s_worst:.4f}")
check("reversed ranking << perfect", s_worst < s_perfect - 0.1)

# (e) refusal
check("score(None, gold)['ndcg'] == 0.0", bench.score(None, g)["ndcg"] == 0.0)
check("score([], gold)['ndcg'] == 0.0", bench.score([], g)["ndcg"] == 0.0)

# extra: parse robustness (JSON array + bullets + prose)
messy = 'Here you go: ["cve-2021-44228", "- CVE-2020-1472", "then CVE-2019-0708."]'
check("parse handles messy/mixed text",
      bench.parse(messy) == ["CVE-2021-44228", "CVE-2020-1472", "CVE-2019-0708"])

# extra: gains are in [0,1] and KEV CVEs are exactly 1.0
all01 = all(0.0 <= v <= 1.0 for v in g.values())
check("all gains in [0,1]", all01)
kev_ok = all(g[c["cve"]] == 1.0 for c in item["cves"] if c["kev"])
check("KEV CVEs have gain 1.0", kev_ok)

print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILURE(S)'}")
sys.exit(1 if fails else 0)
