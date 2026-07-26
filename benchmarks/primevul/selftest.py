"""Offline self-test for the PrimeVul plugin (no API, no model calls).

Verifies: dataset loads, class balance, a real prompt renders, parse() is
robust, and the `mcc` aggregator returns ~1.0 for all-correct, ~-1.0 for
all-wrong, and treats pred=None as the wrong (0) class.

Run:  python3 benchmarks/primevul/selftest.py
"""
import sys
from collections import Counter
from pathlib import Path

# Make the repo importable when run directly.
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from benchmarks.primevul import bench          # noqa: E402
from harness.metrics import AGGREGATORS         # noqa: E402

mcc = AGGREGATORS["mcc"]
fails = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        fails.append(name)


print("=" * 72)
print("PrimeVul plugin self-test")
print("=" * 72)

# --- load + class balance --------------------------------------------------
items = bench.load()
labels = Counter(int(it["target"]) for it in items)
print(f"\nLoaded {len(items)} items. Class balance: "
      f"{labels[1]} vulnerable (1) / {labels[0]} safe (0)")
check("dataset non-empty", len(items) > 0, f"{len(items)} items")
check("both classes present", labels[0] > 0 and labels[1] > 0, dict(labels))

# Deterministic N=60 subset via strata must carry both classes. Mirror a simple
# balanced take: interleave by stratum.
by_stratum = {}
for it in items:
    by_stratum.setdefault(bench.strata(it), []).append(it)
subset, i = [], 0
strata_keys = sorted(by_stratum)
while len(subset) < 60:
    added = False
    for s in strata_keys:
        if i < len(by_stratum[s]):
            subset.append(by_stratum[s][i]); added = True
            if len(subset) == 60:
                break
    if not added:
        break
    i += 1
sub_labels = Counter(int(it["target"]) for it in subset)
check("N=60 subset has both classes", sub_labels[0] > 0 and sub_labels[1] > 0,
      f"n={len(subset)} -> {dict(sub_labels)}")

# --- one full prompt -------------------------------------------------------
example = next(it for it in items if int(it["target"]) == 1)
print("\n" + "-" * 72)
print(f"FULL EXAMPLE PROMPT (idx={example['idx']}, gold={bench.gold(example)}, "
      f"key={bench.key(example)}):")
print("-" * 72)
print(bench.prompt(example))
print("-" * 72)

# --- parse robustness ------------------------------------------------------
parse_cases = [
    ("The function is vulnerable.\nyes", 1),
    ("No", 0),
    ("This looks safe to me.\nno", 0),
    ("Reasoning...\n1", 1),
    ("Reasoning...\n0", 0),
    ("It is not vulnerable.", 0),
    ("**Yes**", 1),
    ("I refuse to answer.", None),   # unparseable -> None
    ("", None),
    (None, None),
]
print("\nparse() cases:")
for raw, expected in parse_cases:
    got = bench.parse(raw)
    check(f"parse({raw!r}) == {expected}", got == expected, f"got {got}")

# --- scoring shape ---------------------------------------------------------
d = bench.score(1, 1)
check("score() returns 'pair' key", "pair" in d, d)
check("score() returns per-item 'mcc'", "mcc" in d, d)
check("score(None, 1) pair carries None pred", bench.score(None, 1)["pair"] == (None, 1),
      bench.score(None, 1))

# --- aggregator: all-correct -> +1 ----------------------------------------
golds = [int(it["target"]) for it in subset]
all_correct = [bench.score(g, g) for g in golds]
m_correct = mcc(all_correct, "mcc")
check("all-correct MCC ~ +1.0", abs(m_correct - 1.0) < 1e-9, f"{m_correct:.4f}")

# --- aggregator: all-wrong -> -1 ------------------------------------------
all_wrong = [bench.score(1 - g, g) for g in golds]
m_wrong = mcc(all_wrong, "mcc")
check("all-wrong MCC ~ -1.0", abs(m_wrong + 1.0) < 1e-9, f"{m_wrong:.4f}")

# --- aggregator: pred=None counts as wrong class (predicted 0) -------------
# If every prediction is None, MCC over (0, gold) pairs = 0 (worst / no skill),
# and it must equal predicting 0 for everything.
all_none = [bench.score(None, g) for g in golds]
all_zero = [bench.score(0, g) for g in golds]
m_none = mcc(all_none, "mcc")
m_zero = mcc(all_zero, "mcc")
check("pred=None == pred=0 (wrong class for vuln items)", abs(m_none - m_zero) < 1e-9,
      f"none={m_none:.4f} zero={m_zero:.4f}")
# A refusal on a vulnerable item must not be counted correct: build a set where
# gold is all-vulnerable and preds all None -> MCC 0 (never +1).
vuln_only = [bench.score(None, 1) for _ in range(20)]
check("all-None on vuln-only is not rewarded (MCC 0, not +1)",
      abs(mcc(vuln_only, "mcc")) < 1e-9, f"{mcc(vuln_only, 'mcc'):.4f}")

# --- summary ---------------------------------------------------------------
print("\n" + "=" * 72)
if fails:
    print(f"RESULT: FAIL ({len(fails)} check(s) failed: {fails})")
    sys.exit(1)
print("RESULT: PASS (all checks passed)")
print("=" * 72)
