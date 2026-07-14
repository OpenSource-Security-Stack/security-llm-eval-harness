"""Generic run loop: items -> prompts -> model calls -> results/*.jsonl.

Benchmark-agnostic. Everything task-specific comes through the Task plugin.
Record schema is identical to the original monolith, so old and new results
files interoperate (and scoring.py reads both).
"""
import concurrent.futures as cf
import json
import time
from collections import Counter, defaultdict

from . import config
from .models import PRICES, ROSTER, call_model, cost_usd


def select_subset(questions, n, key_fn, strata_fn):
    """Deterministic stratified subset: round-robin across sorted strata."""
    by = defaultdict(list)
    for q in sorted(questions, key=lambda x: (strata_fn(x), key_fn(x))):
        by[strata_fn(q)].append(q)
    strata = sorted(by)
    picked, i = [], 0
    while len(picked) < n:
        added = False
        for s in strata:
            if i < len(by[s]):
                picked.append(by[s][i])
                added = True
                if len(picked) == n:
                    break
        if not added:
            break
        i += 1
    return picked


def score_one(model_key, task, tc, prompt):
    """One (model, item) call -> canonical result record."""
    provider, model_id = ROSTER[model_key]
    res = call_model(provider, model_id, prompt)
    gold = task.gold(tc)
    rec = {"model": model_key, "qkey": task.key(tc), "strata": task.strata(tc),
           "correct_options": gold, "latency": round(res.get("latency", 0), 2),
           "prompt_tokens": res.get("prompt_tokens"),
           "completion_tokens": res.get("completion_tokens")}
    rec["cost_usd"] = round(cost_usd(model_key, rec["prompt_tokens"], rec["completion_tokens"]), 6)
    # non-answers score as the metric's WORST value (task.score(None, gold)),
    # not 0.0 — 0 would look perfect on lower-is-better metrics like MAE
    worst = round(task.score(None, gold)[task.metric["id"]], 4)
    if "error" in res:
        rec.update({"error": res["error"], "parse_ok": False, "score": worst,
                    "answered_correctly": "query error"})
        return rec
    pred = task.parse(res["content"])
    if pred is None:
        rec.update({"raw": res["content"][:200], "parse_ok": False, "score": worst,
                    "answered_correctly": "parsing error"})
        return rec
    m = task.score(pred, gold)          # per-item metric dict, e.g. {"jaccard":…, "exact":…}
    rec.update({"model_answers": pred, "parse_ok": True,
                "score": round(m[task.metric["id"]], 4),
                "answered_correctly": "true" if m.get("exact") else "false"})
    return rec


def run(task, models, n=30, workers=8):
    """Run a Task against a model roster; write raw jsonl + summary json."""
    questions = task.load()
    subset = select_subset(questions, n, task.key, task.strata)
    print(f"Task: {task.id}  ({task.name})")
    print(f"Questions: {len(subset)}  |  by strata: {dict(Counter(task.strata(q) for q in subset))}")
    print(f"Models: {models}")
    print("Prices ($/1M in/out): " +
          ", ".join(f"{m}={PRICES[m]['input']}/{PRICES[m]['output']}" for m in models) + "\n")

    prompts = {task.key(q): task.prompt(q) for q in subset}
    jobs = [(mk, tc, prompts[task.key(tc)]) for mk in models for tc in subset]

    records, done = [], 0
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(score_one, mk, task, tc, p): mk for mk, tc, p in jobs}
        for fut in cf.as_completed(futs):
            records.append(fut.result())
            done += 1
            print(f"\r  {done}/{len(jobs)} calls done", end="", flush=True)
    print()

    config.RESULTS.mkdir(exist_ok=True)
    ts = int(time.time())
    out = config.RESULTS / f"{task.id}_n{n}_{ts}.jsonl"
    with open(out, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    summary = summarize(records, models)
    spath = config.RESULTS / f"summary_{task.id}_n{n}_{ts}.json"
    spath.write_text(json.dumps(summary, indent=2))
    print(f"\nRaw:     {out}")
    print(f"Summary: {spath}")
    return records


def summarize(records, models):
    """Per-model console table + summary dicts (same fields as the monolith)."""
    print("\n" + "=" * 92)
    print(f"{'model':<14}{'exact%':>8}{'meanJac':>9}{'parse✓':>8}{'lat(s)':>8}{'ctok/q':>8}"
          f"{'$/1kQ':>9}{'$/correct':>11}")
    print("-" * 92)
    summary = []
    for mk in models:
        rs = [r for r in records if r["model"] == mk]
        n = len(rs)
        exact = sum(r["answered_correctly"] == "true" for r in rs)
        mean_jac = sum(r["score"] for r in rs) / n if n else 0
        exact_pct = 100 * exact / n if n else 0
        parse_pct = 100 * sum(bool(r.get("parse_ok")) for r in rs) / n if n else 0
        lats = [r["latency"] for r in rs if r["latency"]]
        toks = [r["completion_tokens"] for r in rs if r.get("completion_tokens")]
        total_cost = sum(r.get("cost_usd", 0) for r in rs)
        cost_per_1k = total_cost / n * 1000 if n else 0
        cost_per_correct = total_cost / exact if exact else float("inf")
        mean_lat = sum(lats) / len(lats) if lats else 0
        mean_tok = sum(toks) / len(toks) if toks else 0
        cpc_str = "n/a" if cost_per_correct == float("inf") else f"${cost_per_correct:.4f}"
        print(f"{mk:<14}{exact_pct:>7.1f}%{mean_jac:>9.3f}{parse_pct:>7.0f}%{mean_lat:>8.1f}"
              f"{mean_tok:>8.0f}{cost_per_1k:>8.3f} {cpc_str:>10}")
        summary.append({"model": mk, "n": n, "exact_pct": round(exact_pct, 1),
                        "mean_jaccard": round(mean_jac, 4), "parse_pct": round(parse_pct, 1),
                        "mean_latency": round(mean_lat, 2), "mean_completion_tokens": round(mean_tok),
                        "cost_per_1k_questions_usd": round(cost_per_1k, 4),
                        "cost_per_correct_usd": None if exact == 0 else round(cost_per_correct, 6),
                        "total_cost_usd": round(total_cost, 6)})
    print("=" * 92)
    return summary
