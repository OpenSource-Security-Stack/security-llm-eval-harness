"""results -> rankings.json (the contract; see spec/results.schema.json).

For every registered task that can supply per-item results (load_results),
compute single-model stats + the open-mixture row and emit one domain entry.
Also writes rankings.js (`window.RANKINGS`) so the static leaderboard can
<script src> it without fetch/CORS.
"""
import json

from . import config
from .scoring import bootstrap_ci, index, mixture_stats, per_question, single_stats

DISPLAY = {"opus-4.8": "Claude Opus 4.8", "gpt-5.5": "GPT-5.5", "gpt-5.1": "GPT-5.1",
           "minimax-m3": "MiniMax M3", "qwen3-235b": "Qwen3-235B",
           "deepseek-v4": "DeepSeek-V4-Pro", "glm-5.2": "GLM-5.2",
           "gpt-oss-120b": "gpt-oss-120b", "kimi-k3": "Kimi K3"}
CLOSED = {"opus-4.8", "gpt-5.5", "gpt-5.1"}
# kimi-k3 counted open: announced open-source, weights release committed 2026-07-27
# dropped from the analysis (results stay cached; re-add here to restore):
# gpt-5.1 2026-07-12 · qwen3-235b 2026-07-14 (retired endpoint, frozen n=30 rows)
MODEL_ORDER = ["opus-4.8", "gpt-5.5",
               "minimax-m3", "deepseek-v4", "kimi-k3", "glm-5.2", "gpt-oss-120b"]
# The third mixture slot holds whichever model a domain was run with: qwen3-235b
# on the v0 cached domains, deepseek-v4 after Together retired serverless Qwen.
MIX_POOL = ["minimax-m3", "qwen3-235b", "deepseek-v4", "glm-5.2"]

# Domain tab order on the leaderboard (per Manish 2026-07-15). Unlisted domains
# append after, alphabetically.
DOMAIN_ORDER = ["cti", "malware", "deteng", "vulnmgmt"]
MIX_RULE = "majority"
INCLUDE_MIXTURE = False   # 2026-07-12: mixture rows off the leaderboard for now (machinery stays)


def build_domain(task):
    """One task -> (rows sorted best-first, n_questions)."""
    recs = task.load_results()
    byq, correct = index(recs, task)
    present = [m for m in MODEL_ORDER if any(m in byq[q] for q in correct)]
    singles = {m: single_stats(byq, correct, m, task) for m in present}
    rows = []
    for m in present:
        s = singles[m]
        ci = bootstrap_ci(per_question(byq, correct, m, task), task)
        rows.append({"model": DISPLAY.get(m, m), "type": "closed" if m in CLOSED else "open",
                     "score": round(s["mean"], 3),
                     "score_norm": normalize_score(s["mean"], task.metric),
                     "exact_pct": round(s["exact"], 1),
                     "answered_pct": round(s["answered"]), "cost_per_1k_usd": round(s["cost_per_1k"], 2),
                     "latency_s": round(s["latency_s"], 1), "n": s["n"],
                     "ci": [round(ci[0], 3), round(ci[1], 3)]})
    pool = [m for m in MIX_POOL if m in present]
    if INCLUDE_MIXTURE and task.combine and len(pool) >= 2:
        weights = {m: singles[m]["mean"] for m in present}
        sm = mixture_stats(byq, correct, pool, MIX_RULE, task, weights)
        rows.append({"model": f"Mixture — {len(pool)} open models", "type": "mixture",
                     "score": round(sm["mean"], 3), "exact_pct": round(sm["exact"], 1),
                     "answered_pct": round(sm["answered"]), "cost_per_1k_usd": round(sm["cost_per_1k"], 2)})
    reverse = task.metric.get("direction", "higher") == "higher"
    rows.sort(key=lambda r: r["score"], reverse=reverse)
    return rows, len(correct)


def normalize_score(score, metric):
    """Primary metric -> Score in [0, 100], higher = better, monotone.

    higher-direction metrics (jaccard/accuracy/f1/... in [0,1]): score * 100.
    lower-direction metrics: (1 - score/worst) * 100, where metric['worst'] is
    the worst possible value (= what a refusal scores, e.g. 10 for CVSS MAE).
    100 = flawless, 0 = worst possible / refused everything. Display-only —
    rankings are identical to the raw metric's; not comparable across leaves."""
    if metric.get("direction", "higher") == "higher":
        v = score * 100
    else:
        worst = metric["worst"]
        v = (1 - score / worst) * 100
    return round(max(0.0, min(100.0, v)), 1)


def leaf_win_rates(rows, direction):
    """rows: one leaf's model rows. -> {model: fraction of rivals beaten}.
    Ties count 0.5; direction-aware (lower-is-better flips comparisons)."""
    higher = direction == "higher"
    out = {}
    for r in rows:
        wins = 0.0
        for o in rows:
            if o is r:
                continue
            if r["score"] == o["score"]:
                wins += 0.5
            elif (r["score"] > o["score"]) == higher:
                wins += 1.0
        out[r["model"]] = wins / (len(rows) - 1) if len(rows) > 1 else 1.0
    return out


def build_rollups(groups):
    """groups: {domain_id: {"name": str, "leaves": [(leaf_id, leaf_entry), ...]}}
    -> one rollup per domain (INCLUDING single-leaf domains — every domain tab
    gets the same overarching-table structure).

    Headline `score` = mean of the model's per-leaf score_norm (equal weight
    per leaf, same 0-100 higher-better scale as the leaf tables). `win_rate`
    (fraction of rivals beaten, direction-aware, ties 0.5) is kept as a
    secondary signal. `coverage` records leaves present of total."""
    rollups = {}
    for gid, g in groups.items():
        per = {}
        for leaf_id, leaf in g["leaves"]:
            rows = leaf["models"]
            wr = leaf_win_rates(rows, leaf.get("direction", "higher"))
            best = rows[0]["score"]
            for r in rows:
                pm = per.setdefault(r["model"], {"type": r["type"], "rates": [], "norms": [],
                                                 "costs": [], "ans": [], "best_at": []})
                pm["rates"].append(wr[r["model"]])
                pm["norms"].append(r["score_norm"])
                pm["ans"].append(r.get("answered_pct", 100))
                if r.get("cost_per_1k_usd"):
                    pm["costs"].append(r["cost_per_1k_usd"])
                if r["score"] == best:
                    pm["best_at"].append(leaf["name"])
        models = []
        for m, pm in per.items():
            row = {"model": m, "type": pm["type"],
                   "score": round(sum(pm["norms"]) / len(pm["norms"]), 1),
                   "answered_pct_avg": round(sum(pm["ans"]) / len(pm["ans"]), 1),
                   "win_rate": round(sum(pm["rates"]) / len(pm["rates"]), 3),
                   "coverage": [len(pm["rates"]), len(g["leaves"])],
                   "best_at": pm["best_at"]}
            if pm["costs"]:
                # same equal-weight-per-benchmark convention as `score`
                row["cost_per_1k_avg"] = round(sum(pm["costs"]) / len(pm["costs"]), 2)
                row["cost_per_1k_range"] = [round(min(pm["costs"]), 2), round(max(pm["costs"]), 2)]
            models.append(row)
        # Fully-measured models rank first (by score); partial-coverage models are
        # listed beneath them (a domain average over fewer benchmarks isn't
        # comparable to a complete one). Leaf tables are unaffected — there every
        # model competes on the same questions.
        n_leaves = len(g["leaves"])
        models.sort(key=lambda r: (r["coverage"][0] < n_leaves, -r["score"], r["model"]))
        order = (DOMAIN_ORDER.index(gid) + 1 if gid in DOMAIN_ORDER
                 else len(DOMAIN_ORDER) + 1)
        rollups[gid] = {"name": g["name"], "order": order,
                        "leaves": [lid for lid, _ in g["leaves"]],
                        "models": models}
    return rollups


def export(tasks, out_dir=None):
    """Build rankings.json + rankings.js from every task with a results source."""
    out_dir = out_dir or config.REPO
    domains, n_used, suites = {}, 30, []
    for task in tasks:
        if not task.load_results:
            continue
        try:
            rows, n = build_domain(task)
        except Exception as e:
            print(f"skip {task.id}: {type(e).__name__}: {e}")
            continue
        n_used = n
        suites.append(task.suite)
        domains[task.id] = {"name": task.name, "benchmark": task.benchmark_line,
                            "domain": task.domain or task.id,
                            "domain_name": task.domain_name or task.name,
                            "metric": task.metric["id"],
                            "direction": task.metric.get("direction", "higher"),
                            "models": rows}
    if not domains:
        print("no domains exported — check results/ and dataset paths")
        return None

    # domain rollups: group exported leaves by their task's parent domain
    groups = {}
    for task in tasks:
        if task.id in domains and task.domain:
            g = groups.setdefault(task.domain, {"name": task.domain_name, "leaves": []})
            g["leaves"].append((task.id, domains[task.id]))
    rollups = build_rollups(groups)

    out = {"meta": {"suite": suites[0] if len(set(suites)) == 1 else "multiple suites",
                    "n": n_used, "generated": "unset (stamp on publish)"},
           "domains": domains}
    if rollups:
        out["rollups"] = rollups
        for gid, ru in rollups.items():
            top = ru["models"][0]
            print(f"rollup {gid}: {len(ru['leaves'])} leaves, top: {top['model']} "
                  f"win_rate {top['win_rate']}")

    (out_dir / "rankings.json").write_text(json.dumps(out, indent=2))
    js = "// generated by scripts/export.py — do not edit by hand\n" \
         "window.RANKINGS = " + json.dumps(out, indent=2) + ";\n"
    (out_dir / "rankings.js").write_text(js)
    print(f"wrote rankings.json + rankings.js ({len(domains)} domains, n={n_used})")
    print("copy rankings.js -> ../security-llm-leaderboard/data/rankings.js to update the site")
    return out
