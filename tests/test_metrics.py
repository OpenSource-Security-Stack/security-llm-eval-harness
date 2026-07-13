#!/usr/bin/env python3
"""Hand-computed test cases for every metric primitive + aggregator.

Run: python3 tests/test_metrics.py   (no deps, exits non-zero on failure)
"""
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness.metrics import (AGGREGATORS, abs_error, exact_match, hier_match,  # noqa: E402
                             jaccard, ndcg_at_k, pass_at_k, set_prf)


def close(a, b, tol=1e-9):
    assert abs(a - b) < tol, f"{a} != {b}"


# --- per-item scorers --------------------------------------------------------
# jaccard
close(jaccard(["A", "B"], ["A", "B"]), 1.0)
close(jaccard(["A"], ["A", "B"]), 0.5)
close(jaccard([], ["A"]), 0.0)
close(jaccard([], []), 0.0)

# exact_match (normalization + None)
close(exact_match(" cwe-79 ", "CWE-79"), 1.0)
close(exact_match("CWE-89", "CWE-79"), 0.0)
close(exact_match(None, "CWE-79"), 0.0)

# abs_error (regression; None/garbage -> worst, never 0)
close(abs_error(7.5, 9.0, worst=10.0), 1.5)
close(abs_error("7.5", 7.5, worst=10.0), 0.0)
close(abs_error(None, 5.0, worst=10.0), 10.0)
close(abs_error("N/A", 5.0, worst=10.0), 10.0)

# set_prf: pred {A,B,C} vs gold {B,C,D} -> tp=2 fp=1 fn=1, P=R=F1=2/3
d = set_prf(["A", "B", "C"], ["B", "C", "D"])
assert (d["tp"], d["fp"], d["fn"]) == (2, 1, 1)
close(d["precision"], 2 / 3)
close(d["recall"], 2 / 3)
close(d["f1"], 2 / 3)
d = set_prf(None, ["X"])            # unanswered extraction
assert (d["tp"], d["fp"], d["fn"]) == (0, 0, 1) and d["f1"] == 0.0

# ndcg@3: gains a=3,b=2,c=1; model order [b,a,c]
# DCG = 2/log2(2) + 3/log2(3) + 1/log2(4); IDCG = 3/log2(2) + 2/log2(3) + 1/log2(4)
dcg = 2 + 3 / math.log2(3) + 0.5
idcg = 3 + 2 / math.log2(3) + 0.5
close(ndcg_at_k(["b", "a", "c"], {"a": 3, "b": 2, "c": 1}, 3), dcg / idcg)
close(ndcg_at_k(["a", "b", "c"], {"a": 3, "b": 2, "c": 1}, 3), 1.0)  # perfect order
close(ndcg_at_k(None, {"a": 1}, 3), 0.0)                              # no answer

# pass@k: n=5 samples, c=2 correct, k=1 -> c/n = 0.4; c>=n-k+... edge: c=5 -> 1.0
close(pass_at_k(5, 2, 1), 0.4)
close(pass_at_k(5, 5, 1), 1.0)
close(pass_at_k(5, 0, 3), 0.0)
# n=4, c=2, k=2 -> 1 - C(2,2)/C(4,2) = 1 - 1/6
close(pass_at_k(4, 2, 2), 1 - 1 / 6)

# hier_match: CWE-787 (OOB write) child of CWE-119
parents = {"CWE-787": "CWE-119", "CWE-125": "CWE-119"}
close(hier_match("CWE-787", "CWE-787", parents), 1.0)
close(hier_match("CWE-787", "CWE-119", parents), 0.75)   # child <-> parent
close(hier_match("CWE-787", "CWE-125", parents), 0.75)   # siblings
close(hier_match("CWE-79", "CWE-787", parents), 0.0)
close(hier_match(None, "CWE-787", parents), 0.0)

# --- aggregators --------------------------------------------------------------
mean = AGGREGATORS["mean"]
close(mean([{"m": 1.0}, {"m": 0.0}, {"m": 0.5}], "m"), 0.5)
close(mean([], "m"), 0.0)

# macro_f1: 2 classes. pairs: (A,A),(A,B),(B,B),(None,B)
#  A: tp=1 fp=1 fn=0 -> f1=2/3 ; B: tp=1 fp=0 fn=2 -> f1=0.5 ; macro = 7/12
macro = AGGREGATORS["macro_f1"]
items = [{"pair": p} for p in [("A", "A"), ("A", "B"), ("B", "B"), (None, "B")]]
close(macro(items, "_"), (2 / 3 + 0.5) / 2)

# micro_f1 pools counts: (tp,fp,fn) = (2,1,1)+(0,0,1) -> 2*2/(2*2+1+2) = 4/7
micro = AGGREGATORS["micro_f1"]
close(micro([{"tp": 2, "fp": 1, "fn": 1}, {"tp": 0, "fp": 0, "fn": 1}], "_"), 4 / 7)

# mcc: perfect prediction -> 1.0; inverted -> -1.0; None counts as negative class
mcc = AGGREGATORS["mcc"]
perfect = [{"pair": (1, 1)}, {"pair": (0, 0)}, {"pair": (1, 1)}, {"pair": (0, 0)}]
close(mcc(perfect, "_"), 1.0)
inverted = [{"pair": (0, 1)}, {"pair": (1, 0)}, {"pair": (0, 1)}, {"pair": (1, 0)}]
close(mcc(inverted, "_"), -1.0)
close(mcc([{"pair": (None, 1)}, {"pair": (0, 0)},
           {"pair": (1, 1)}, {"pair": (0, 0)}], "_"),
      mcc([{"pair": (0, 1)}, {"pair": (0, 0)},
           {"pair": (1, 1)}, {"pair": (0, 0)}], "_"))

# --- aggregator plumbing through a fake Task -----------------------------------
from harness.scoring import bootstrap_ci  # noqa: E402


class FakeTask:
    id = "fake"
    metric = {"id": "accuracy", "direction": "higher", "aggregate": "mean"}

    @staticmethod
    def score(pred, gold):
        return {"accuracy": exact_match(pred, gold), "exact": exact_match(pred, gold) == 1.0}


items = [{"accuracy": 1.0}, {"accuracy": 0.0}] * 15
lo, hi = bootstrap_ci(items, FakeTask())
assert 0.2 < lo < 0.5 < hi < 0.8, (lo, hi)     # CI brackets the 0.5 mean

print("all metric tests pass ✓")
