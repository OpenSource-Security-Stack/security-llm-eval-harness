#!/usr/bin/env python3
"""Rollup math against the hand-worked 3-leaf example (mixed metrics/directions).

Run: python3 tests/test_rollup.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness.export import build_rollups, leaf_win_rates  # noqa: E402


def close(a, b, tol=1e-9):
    assert abs(a - b) < tol, f"{a} != {b}"


def rows(*pairs):
    return [{"model": m, "type": "open", "score": s, "cost_per_1k_usd": 1.0}
            for m, s in pairs]


# Leaf 1 — jaccard (higher): Opus .75 > {MiniMax, GLM} .72 > GPT .70
l1 = {"name": "Reports", "direction": "higher", "metric": "jaccard",
      "models": rows(("Opus", 0.75), ("MiniMax", 0.72), ("GLM", 0.72), ("GPT", 0.70))}
wr = leaf_win_rates(l1["models"], "higher")
close(wr["Opus"], 1.0)
close(wr["MiniMax"], 0.5)    # beats GPT, ties GLM -> 1.5/3
close(wr["GLM"], 0.5)
close(wr["GPT"], 0.0)

# Leaf 2 — accuracy (higher): GPT .62 > MiniMax .60 > Opus .55 > GLM .48
l2 = {"name": "Logs", "direction": "higher", "metric": "accuracy",
      "models": rows(("GPT", 0.62), ("MiniMax", 0.60), ("Opus", 0.55), ("GLM", 0.48))}

# Leaf 3 — MAE (LOWER): MiniMax 0.9 best, then GPT 1.0, Opus 1.2, GLM 1.5
l3 = {"name": "Triage", "direction": "lower", "metric": "mae",
      "models": rows(("MiniMax", 0.9), ("GPT", 1.0), ("Opus", 1.2), ("GLM", 1.5))}
wr = leaf_win_rates(l3["models"], "lower")
close(wr["MiniMax"], 1.0)    # direction flip: smallest wins
close(wr["GLM"], 0.0)

# Domain rollup — the worked example: MiniMax .722, GPT = Opus .556, GLM .167
ru = build_rollups({"soc": {"name": "SOC", "leaves": [("l1", l1), ("l2", l2), ("l3", l3)]}})
models = {m["model"]: m for m in ru["soc"]["models"]}
close(models["MiniMax"]["win_rate"], round((0.5 + 2 / 3 + 1.0) / 3, 3))       # 0.722
close(models["GPT"]["win_rate"], round((0.0 + 1.0 + 2 / 3) / 3, 3))           # 0.556
close(models["Opus"]["win_rate"], round((1.0 + 1 / 3 + 1 / 3) / 3, 3))        # 0.556
close(models["GLM"]["win_rate"], round(0.5 / 3, 3))                           # 0.167
assert ru["soc"]["models"][0]["model"] == "MiniMax"                # sorted best-first
assert models["MiniMax"]["best_at"] == ["Triage"]                  # only leaf it won
assert models["Opus"]["best_at"] == ["Reports"]
assert models["MiniMax"]["coverage"] == [3, 3]

# Ragged coverage: model missing from a leaf -> mean over PRESENT leaves + badge
l2b = {"name": "Logs", "direction": "higher", "metric": "accuracy",
       "models": rows(("GPT", 0.62), ("Opus", 0.55), ("GLM", 0.48))}   # no MiniMax
ru = build_rollups({"soc": {"name": "SOC", "leaves": [("l1", l1), ("l2", l2b)]}})
mm = {m["model"]: m for m in ru["soc"]["models"]}["MiniMax"]
assert mm["coverage"] == [1, 2]
close(mm["win_rate"], 0.5)   # only leaf 1

# Single-leaf domains produce NO rollup
assert build_rollups({"solo": {"name": "Solo", "leaves": [("l1", l1)]}}) == {}

# Exact tie handling: two models tie for best -> both get best_at
l4 = {"name": "T", "direction": "higher", "metric": "accuracy",
      "models": rows(("A", 0.5), ("B", 0.5), ("C", 0.1))}
ru = build_rollups({"d": {"name": "D", "leaves": [("l4", l4), ("l1", l1)]}})
d = {m["model"]: m for m in ru["d"]["models"]}
assert "T" in d["A"]["best_at"] and "T" in d["B"]["best_at"]

print("all rollup tests pass ✓")
