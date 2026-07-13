"""Turn per-item result records into model stats + mixture stats.

Works on the canonical record shape written by runner.run (and by the older
monolith — the schema is unchanged): model, _qid, model_answers, parse_ok,
correct_options, prompt_tokens, completion_tokens, latency.

Mixture = offline aggregation of the pool's per-question letter-sets, scored
with the same Jaccard as single models. Cost of a mixture is the SUM of its
members; latency is the MAX (members run in parallel).
"""
from collections import defaultdict

from .metrics import jaccard, normalize_letters
from .models import cost_usd


def norm_gold(c):
    return tuple(str(x).strip().upper()[:1] for x in c)


def index(recs):
    """records -> (byq: qid -> model -> {answers, answered, cost, latency},
                   correct: qid -> gold letters)"""
    byq = defaultdict(dict)
    correct = {}
    for r in recs:
        qid = r["_qid"]
        answers = normalize_letters(r.get("model_answers") or [])
        answered = bool(r.get("parse_ok")) and len(answers) > 0
        cost = r.get("cost_usd")
        if cost is None:
            cost = cost_usd(r["model"], r.get("prompt_tokens"), r.get("completion_tokens"))
        byq[qid][r["model"]] = {"answers": answers, "answered": answered,
                                "cost": cost, "latency": r.get("latency") or 0}
        correct[qid] = norm_gold(r["correct_options"])
    return byq, correct


def aggregate(members, rule, weights=None):
    """members: list of {answers, answered, _model}. -> (letters, answered_any).

    Rules: majority (>= half), union (any), intersect (all), weighted
    (meanJac-weighted majority), thresh-k (>= k members)."""
    voting = [m for m in members if m["answered"]]
    if not voting:
        return [], False
    n = len(voting)
    cand = set().union(*[set(m["answers"]) for m in voting])
    keep = []
    for L in cand:
        pickers = [m for m in voting if L in m["answers"]]
        cnt = len(pickers)
        if rule == "union":
            ok = cnt >= 1
        elif rule == "intersect":
            ok = cnt == n
        elif rule == "majority":
            ok = cnt * 2 >= n
        elif rule.startswith("thresh-"):
            ok = cnt >= int(rule.split("-")[1])
        elif rule == "weighted":
            wsum = sum(weights[m["_model"]] for m in voting)
            wpick = sum(weights[m["_model"]] for m in pickers)
            ok = wpick * 2 >= wsum
        else:
            raise ValueError(rule)
        if ok:
            keep.append(L)
    return sorted(keep), True


def score_series(answers_by_q, correct):
    """answers_by_q: qid -> (letters, answered). -> (exact%, meanJac, answered%)."""
    n = len(correct)
    ex = mj = ans = 0
    for qid, gt in correct.items():
        letters, answered = answers_by_q[qid]
        j = jaccard(letters, gt) if answered else 0.0
        mj += j
        ex += 1 if j == 1.0 else 0
        ans += 1 if answered else 0
    return 100 * ex / n, mj / n, 100 * ans / n


def single_stats(byq, correct, model):
    ans = {}
    cost = 0.0
    for qid in correct:
        m = byq[qid].get(model)
        if m:
            ans[qid] = (m["answers"], m["answered"])
            cost += m["cost"]
        else:
            ans[qid] = ([], False)
    ex, mj, ap = score_series(ans, correct)
    return {"exact": ex, "meanJac": mj, "answered": ap,
            "cost_per_1k": cost / len(correct) * 1000}


def mixture_stats(byq, correct, pool, rule, weights=None):
    ans = {}
    cost = 0.0
    lat = 0.0
    for qid in correct:
        members = []
        for mdl in pool:
            m = byq[qid].get(mdl)
            if m:
                mm = dict(m)
                mm["_model"] = mdl
                members.append(mm)
                cost += m["cost"]                                  # sum of members
        lat += max([m["latency"] for m in members], default=0)     # parallel -> max
        ans[qid] = aggregate(members, rule, weights)
    ex, mj, ap = score_series(ans, correct)
    return {"exact": ex, "meanJac": mj, "answered": ap,
            "cost_per_1k": cost / len(correct) * 1000,
            "lat_per_q": lat / len(correct)}


def oracle(byq, correct, pool):
    """Upper bounds (peek at the key): ceiling for a perfect per-question router."""
    n = len(correct)
    any_exact = 0
    best_jac = 0.0
    for qid, gt in correct.items():
        js = [jaccard(m["answers"], gt) for mdl in pool
              if (m := byq[qid].get(mdl)) and m["answered"]]
        if js:
            best_jac += max(js)
            if max(js) == 1.0:
                any_exact += 1
    return {"any_exact": 100 * any_exact / n, "best_jac": best_jac / n}
