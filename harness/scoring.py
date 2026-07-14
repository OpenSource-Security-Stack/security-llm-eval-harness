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

from .metrics import AGGREGATORS
from .models import cost_usd


def _agg_fn(task):
    name = task.metric.get("aggregate", "mean")
    if name not in AGGREGATORS:
        raise KeyError(f"unknown aggregate '{name}' (task {task.id}); known: {sorted(AGGREGATORS)}")
    return AGGREGATORS[name]


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
        # Recompute cost from tokens at current verified prices — stored per-record
        # costs may embed prices that were wrong at run time (2026-07-13 audit found
        # both manual placeholders off by 3-4x). Stored value is the fallback only
        # when token counts are missing.
        cost = cost_usd(r["model"], r.get("prompt_tokens"), r.get("completion_tokens"))
        if not cost:
            cost = r.get("cost_usd") or 0.0
        byq[qid][r["model"]] = {"pred": pred, "answered": answered,
                                "cost": cost, "latency": r.get("latency") or 0}
        correct[qid] = r["correct_options"]
    return byq, correct


def _score_items(answers_by_q, correct, task):
    """answers_by_q: qid -> (pred, answered). Scores EVERY item — unanswered ones
    as task.score(None, gold), which per-item scorers map to that metric's worst.
    Returns (items: list of per-item dicts, exact%, answered%)."""
    n = len(correct)
    items, ex, ans = [], 0, 0
    for qid, gold in correct.items():
        pred, answered = answers_by_q[qid]
        m = task.score(pred if answered else None, gold)
        items.append(m)
        ex += 1 if (answered and m.get("exact")) else 0
        ans += 1 if answered else 0
    return items, 100 * ex / n, 100 * ans / n


def _series_stats(answers_by_q, correct, task):
    """-> (exact%, aggregated metric, answered%). Aggregation per task.metric."""
    items, ex, ans = _score_items(answers_by_q, correct, task)
    return ex, _agg_fn(task)(items, task.metric["id"]), ans


def attempted(byq, correct, model):
    """The questions this model actually has records for. Stats are computed
    over this set, NOT the domain union — a legacy model that predates newer
    questions (e.g. a retired endpoint) is scored on what it attempted, with
    the per-row `n` disclosing the smaller basis. Subsets are nested, so a
    smaller n is always a prefix of the larger ones."""
    return {qid: gold for qid, gold in correct.items() if model in byq[qid]}


def single_stats(byq, correct, model, task):
    corr = attempted(byq, correct, model)
    ans = {}
    cost = 0.0
    lats = []
    for qid in corr:
        m = byq[qid][model]
        ans[qid] = (m["pred"], m["answered"])
        cost += m["cost"]
        if m["latency"]:
            lats.append(m["latency"])
    ex, mv, ap = _series_stats(ans, corr, task)
    return {"exact": ex, "mean": mv, "answered": ap, "n": len(corr),
            "cost_per_1k": cost / len(corr) * 1000 if corr else 0.0,
            "latency_s": sum(lats) / len(lats) if lats else 0.0}


def per_question(byq, correct, model, task):
    """Per-item score dicts for one model over its attempted questions.
    The raw series behind the domain score — feeds the bootstrap CI."""
    corr = attempted(byq, correct, model)
    ans = {qid: (byq[qid][model]["pred"], byq[qid][model]["answered"]) for qid in corr}
    items, _, _ = _score_items(ans, corr, task)
    return items


def bootstrap_ci(items, task, n_boot=10000, alpha=0.05, seed=1337):
    """Percentile bootstrap CI on the domain score: resample items with
    replacement, re-aggregate (mean, macro_f1, mcc, ...) each time. Fixed
    seed -> reproducible exports."""
    import random
    if not items:
        return [0.0, 0.0]
    agg, mid = _agg_fn(task), task.metric["id"]
    rng = random.Random(seed)
    n = len(items)
    stats = sorted(agg([rng.choice(items) for _ in range(n)], mid)
                   for _ in range(n_boot))
    lo = stats[int(alpha / 2 * n_boot)]
    hi = stats[min(int((1 - alpha / 2) * n_boot), n_boot - 1)]
    return [lo, hi]


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
