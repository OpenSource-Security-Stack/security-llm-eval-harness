#!/usr/bin/env python3
"""Rollup math against the hand-worked 3-leaf example (mixed metrics/directions).

Run: python3 tests/test_rollup.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness.export import build_rollups, leaf_win_rates, normalize_score  # noqa: E402


def close(a, b, tol=1e-9):
    assert abs(a - b) < tol, f"{a} != {b}"


def rows(*triples):
    """(model, raw score, score_norm) rows."""
    return [{"model": m, "type": "open", "score": s, "score_norm": n,
             "cost_per_1k_usd": 1.0} for m, s, n in triples]


# Leaf 1 — jaccard (higher): Opus .75 > {MiniMax, GLM} .72 > GPT .70
l1 = {"name": "Reports", "direction": "higher", "metric": "jaccard",
      "models": rows(("Opus", 0.75, 75.0), ("MiniMax", 0.72, 72.0),
                     ("GLM", 0.72, 72.0), ("GPT", 0.70, 70.0))}
wr = leaf_win_rates(l1["models"], "higher")
close(wr["Opus"], 1.0)
close(wr["MiniMax"], 0.5)    # beats GPT, ties GLM -> 1.5/3
close(wr["GLM"], 0.5)
close(wr["GPT"], 0.0)

# Leaf 2 — accuracy (higher): GPT .62 > MiniMax .60 > Opus .55 > GLM .48
l2 = {"name": "Logs", "direction": "higher", "metric": "accuracy",
      "models": rows(("GPT", 0.62, 62.0), ("MiniMax", 0.60, 60.0),
                     ("Opus", 0.55, 55.0), ("GLM", 0.48, 48.0))}

# Leaf 3 — MAE (LOWER, worst=10): MiniMax 0.9 best -> norm 91, GPT 90, Opus 88, GLM 85
l3 = {"name": "Triage", "direction": "lower", "metric": "mae",
      "models": rows(("MiniMax", 0.9, 91.0), ("GPT", 1.0, 90.0),
                     ("Opus", 1.2, 88.0), ("GLM", 1.5, 85.0))}
wr = leaf_win_rates(l3["models"], "lower")
close(wr["MiniMax"], 1.0)    # direction flip: smallest raw wins
close(wr["GLM"], 0.0)

# Domain rollup — headline score = mean of per-leaf score_norm
ru = build_rollups({"soc": {"name": "SOC", "leaves": [("l1", l1), ("l2", l2), ("l3", l3)]}})
models = {m["model"]: m for m in ru["soc"]["models"]}
close(models["MiniMax"]["score"], round((72 + 60 + 91) / 3, 1))   # 74.3
close(models["GPT"]["score"], 74.0)
close(models["Opus"]["score"], round((75 + 55 + 88) / 3, 1))      # 72.7
close(models["GLM"]["score"], round((72 + 48 + 85) / 3, 1))       # 68.3
assert [m["model"] for m in ru["soc"]["models"]] == ["MiniMax", "GPT", "Opus", "GLM"]
# win_rate retained as the secondary/router signal (hand-worked values)
close(models["MiniMax"]["win_rate"], round((0.5 + 2 / 3 + 1.0) / 3, 3))   # 0.722
close(models["GPT"]["win_rate"], round((0.0 + 1.0 + 2 / 3) / 3, 3))       # 0.556
close(models["GLM"]["win_rate"], round(0.5 / 3, 3))                       # 0.167
assert models["MiniMax"]["best_at"] == ["Triage"]
assert models["Opus"]["best_at"] == ["Reports"]
assert models["MiniMax"]["coverage"] == [3, 3]

# Ragged coverage: model missing from a leaf -> mean over PRESENT leaves + badge
l2b = {"name": "Logs", "direction": "higher", "metric": "accuracy",
       "models": rows(("GPT", 0.62, 62.0), ("Opus", 0.55, 55.0), ("GLM", 0.48, 48.0))}
ru = build_rollups({"soc": {"name": "SOC", "leaves": [("l1", l1), ("l2", l2b)]}})
mm = {m["model"]: m for m in ru["soc"]["models"]}["MiniMax"]
assert mm["coverage"] == [1, 2]
close(mm["score"], 72.0)     # only leaf 1
close(mm["win_rate"], 0.5)

# Single-leaf domains DO get a rollup now (uniform structure everywhere):
# headline score == the leaf's score_norm, win_rate == the leaf win rate
ru = build_rollups({"solo": {"name": "Solo", "leaves": [("l1", l1)]}})
solo = {m["model"]: m for m in ru["solo"]["models"]}
close(solo["Opus"]["score"], 75.0)
close(solo["Opus"]["win_rate"], 1.0)
assert solo["Opus"]["coverage"] == [1, 1]
assert [m["model"] for m in ru["solo"]["models"]][0] == "Opus"

# Exact tie handling: two models tie for best -> both get best_at
l4 = {"name": "T", "direction": "higher", "metric": "accuracy",
      "models": rows(("A", 0.5, 50.0), ("B", 0.5, 50.0), ("C", 0.1, 10.0))}
ru = build_rollups({"d": {"name": "D", "leaves": [("l4", l4), ("l1", l1)]}})
d = {m["model"]: m for m in ru["d"]["models"]}
assert "T" in d["A"]["best_at"] and "T" in d["B"]["best_at"]

print("all rollup tests pass ✓")

# --- normalize_score (display Score 0-100) ------------------------------------
close(normalize_score(0.577, {"direction": "higher"}), 57.7)
close(normalize_score(0.62, {"direction": "higher"}), 62.0)
close(normalize_score(1.0, {"direction": "higher"}), 100.0)
close(normalize_score(1.274, {"direction": "lower", "worst": 10.0}), 87.3)   # CVSS MAE
close(normalize_score(10.0, {"direction": "lower", "worst": 10.0}), 0.0)     # refused all
close(normalize_score(0.0, {"direction": "lower", "worst": 10.0}), 100.0)    # perfect
print("normalize_score tests pass ✓")
