"""Turn per-item result records into model stats + mixture stats.

Metric-agnostic: the Task supplies score(pred, gold) (per-item metric dict),
answered(pred) (does this prediction count as an answer?), and optionally
combine(members, rule, weights) (how a pool merges predictions — mixtures are
only built for tasks that define it).

Works on the canonical record shape written by runner.run (and by the older
monolith — the schema is unchanged): model, _qid, model_answers, parse_ok,
correct_options, prompt_tokens, completion_tokens, latency, cost_usd.

Mixture cost is the SUM of its members; latency is the MAX (parallel).
"""
from collections import defaultdict

from .models import cost_usd


def norm_gold(c):
    return tuple(str(x).strip().upper()[:1] for x in c)


def index(recs, task):
    """records -> (byq: qid -> model -> {pred, answered, cost, latency},
                   correct: qid -> gold as stored)"""
    answered_fn = task.answered or (lambda p: bool(p))
    byq = defaultdict(dict)
    correct = {}
    for r in recs:
        qid = r["_qid"]
        pred = r.get("model_answers")
        answered = bool(r.get("parse_ok")) and answered_fn(pred)
        cost = r.get("cost_usd")
        if cost is None:
            cost = cost_usd(r["model"], r.get("prompt_tokens"), r.get("completion_tokens"))
        byq[qid][r["model"]] = {"pred": pred, "answered": answered,
                                "cost": cost, "latency": r.get("latency") or 0}
        correct[qid] = r["correct_options"]
    return byq, correct


def _series_stats(answers_by_q, correct, task):
    """answers_by_q: qid -> (pred, answered). -> (exact%, mean metric, answered%)."""
    mid = task.metric["id"]
    n = len(correct)
    ex = mv = ans = 0
    for qid, gold in correct.items():
        pred, answered = answers_by_q[qid]
        if answered:
            m = task.score(pred, gold)
            mv += m[mid]
            ex += 1 if m.get("exact") else 0
            ans += 1
    return 100 * ex / n, mv / n, 100 * ans / n


def single_stats(byq, correct, model, task):
    ans = {}
    cost = 0.0
    for qid in correct:
        m = byq[qid].get(model)
        if m:
            ans[qid] = (m["pred"], m["answered"])
            cost += m["cost"]
        else:
            ans[qid] = (None, False)
    ex, mv, ap = _series_stats(ans, correct, task)
    return {"exact": ex, "mean": mv, "answered": ap,
            "cost_per_1k": cost / len(correct) * 1000}


def mixture_stats(byq, correct, pool, rule, task, weights=None):
    """Requires task.combine. Combines the pool's predictions per question,
    then scores the combined prediction like any single model's."""
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
        ans[qid] = task.combine(members, rule, weights)
    ex, mv, ap = _series_stats(ans, correct, task)
    return {"exact": ex, "mean": mv, "answered": ap,
            "cost_per_1k": cost / len(correct) * 1000,
            "lat_per_q": lat / len(correct)}


def oracle(byq, correct, pool, task):
    """Upper bounds (peek at the key): ceiling for a perfect per-question router."""
    mid = task.metric["id"]
    n = len(correct)
    any_exact = 0
    best = 0.0
    for qid, gold in correct.items():
        vals = [task.score(m["pred"], gold) for mdl in pool
                if (m := byq[qid].get(mdl)) and m["answered"]]
        if vals:
            best += max(v[mid] for v in vals)
            if any(v.get("exact") for v in vals):
                any_exact += 1
    return {"any_exact": 100 * any_exact / n, "best": best / n}
