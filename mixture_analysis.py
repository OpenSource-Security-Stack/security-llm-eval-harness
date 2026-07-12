#!/usr/bin/env python3
"""Mixture-of-models analysis (offline, no API spend).

Question: can a MIXTURE of open-weight models match the closed models
(Opus 4.8 / GPT-5.5) on malware analysis or threat-intel reasoning?

We already have every model's per-question answer cached in
results/{malware,cti}_n30_merged7.jsonl. A "mixture" is just an offline
aggregation of those per-question letter-sets. For each question we combine
the pool members' answers with several rules, then score the combined answer
with the SAME Jaccard metric as the harness.

Aggregation rules (over the pool members that returned a usable answer):
  majority  — a letter is kept if >= half of answering members picked it
  union     — kept if ANY member picked it            (recall-biased)
  intersect — kept if ALL members picked it           (precision-biased)
  weighted  — weighted majority, weight = member's own meanJac on the task
  thresh-k  — kept if >= k members picked it           (sweep, printed)

Oracle upper bounds (NOT deployable — they peek at the answer key; they tell
us whether the pool COLLECTIVELY covers the answer, i.e. the ceiling a perfect
per-question router could reach):
  any-exact — question counts correct if ANY member was exactly right
  best-jac  — meanJac if you could pick each question's best member

Cost note: a mixture COSTS THE SUM of its members (you run them all). Latency
is the MAX (you run them in parallel). Both are reported so the accuracy is
weighed against real spend.
"""
import importlib.util
import json
import math
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

# Reuse the harness for prices + scoring (identical methodology).
_spec = importlib.util.spec_from_file_location("h", HERE / "run_cybersoceval.py")
h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h)

CLOSED = ["opus-4.8", "gpt-5.5"]
ANCHOR = "gpt-5.5"                 # closed model the mixtures are compared against
POOLS = {
    "OSS-3 (minimax+qwen+glm)":      ["minimax-m3", "qwen3-235b", "glm-5.2"],
    "OSS-4 (+gpt-oss-120b)":         ["minimax-m3", "qwen3-235b", "glm-5.2", "gpt-oss-120b"],
}
ALL_MODELS = ["opus-4.8", "gpt-5.5",
              "minimax-m3", "qwen3-235b", "glm-5.2", "gpt-oss-120b"]


# ---------------------------------------------------------------------------
# Load cached records -> canonical question ids so all models align
# ---------------------------------------------------------------------------
def _norm(c):
    return tuple(str(x).strip().upper()[:1] for x in c)


def load_cti():
    recs = [json.loads(l) for l in open(HERE / "results" / "cti_n30_merged7.jsonl") if l.strip()]
    for r in recs:
        r["_qid"] = r["qkey"]                      # qkey is stable across models
    return recs


def load_malware():
    """Two schema families: older runs carry sha256/topic/difficulty; newer runs
    (gpt-5.5, opus) carry qkey == sha256+question. Map both to the canonical
    question id (= sha256+question) via the harness's own subset."""
    qs = h.mal_load()
    sub = h.select_subset(qs, 30, h.mal_key, h.mal_strata)
    canon_id = {h.mal_key(q): h.mal_key(q) for q in sub}          # id == mal_key
    composite = {(q["sha256"], _norm(q["correct_options"]), q["topic"], q["difficulty"]): h.mal_key(q)
                 for q in sub}
    recs = [json.loads(l) for l in open(HERE / "results" / "malware_n30_merged7.jsonl") if l.strip()]
    for r in recs:
        if "qkey" in r and r["qkey"] in canon_id:                 # newer family
            r["_qid"] = r["qkey"]
        else:                                                     # older family
            r["_qid"] = composite[(r["sha256"], _norm(r["correct_options"]),
                                   r["topic"], r["difficulty"])]
    return recs


# ---------------------------------------------------------------------------
# index: qid -> model -> {answers, answered, correct, cost, latency}
# ---------------------------------------------------------------------------
def index(recs):
    byq = defaultdict(dict)
    correct = {}
    for r in recs:
        qid = r["_qid"]
        answers = h.normalize_letters(r.get("model_answers") or [])
        answered = bool(r.get("parse_ok")) and len(answers) > 0
        cost = h.cost_usd(r["model"], r.get("prompt_tokens"), r.get("completion_tokens"))
        byq[qid][r["model"]] = {"answers": answers, "answered": answered,
                                "cost": cost, "latency": r.get("latency") or 0}
        correct[qid] = _norm(r["correct_options"])
    return byq, correct


# ---------------------------------------------------------------------------
# Aggregation rules -> combined letter-set for one question
# ---------------------------------------------------------------------------
def aggregate(members, rule, weights=None):
    """members: list of {answers, answered}. Returns (letters, answered_any)."""
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
            ok = cnt * 2 >= n                          # >= half
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


# ---------------------------------------------------------------------------
# Stats helpers
# ---------------------------------------------------------------------------
def score_series(answers_by_q, correct):
    """answers_by_q: qid -> (letters, answered). Returns exact%, meanJac, answered%."""
    n = len(correct)
    ex = mj = ans = 0
    for qid, gt in correct.items():
        letters, answered = answers_by_q[qid]
        j = h.jaccard(letters, gt) if answered else 0.0
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
                mm = dict(m); mm["_model"] = mdl
                members.append(mm)
                cost += m["cost"]                       # sum of members
        lat += max([m["latency"] for m in members], default=0)   # parallel -> max
        ans[qid] = aggregate(members, rule, weights)
    ex, mj, ap = score_series(ans, correct)
    return {"exact": ex, "meanJac": mj, "answered": ap,
            "cost_per_1k": cost / len(correct) * 1000,
            "lat_per_q": lat / len(correct)}


def oracle(byq, correct, pool):
    n = len(correct)
    any_exact = 0
    best_jac = 0.0
    for qid, gt in correct.items():
        js = []
        for mdl in pool:
            m = byq[qid].get(mdl)
            if m and m["answered"]:
                js.append(h.jaccard(m["answers"], gt))
        if js:
            best_jac += max(js)
            if max(js) == 1.0:
                any_exact += 1
    return {"any_exact": 100 * any_exact / n, "best_jac": best_jac / n}


# ---------------------------------------------------------------------------
def run_task(name, recs, out_lines):
    byq, correct = index(recs)
    N = len(correct)
    # weights for weighted-majority = each model's own meanJac on this task
    weights = {m: single_stats(byq, correct, m)["meanJac"] for m in ALL_MODELS}

    out_lines.append(f"\n## {name}  (N={N} questions)\n")

    # 1) single models
    out_lines.append("### Single models (reference)\n")
    out_lines.append("| Model | exact% | meanJac | answered% | $/1k Q |")
    out_lines.append("|---|--:|--:|--:|--:|")
    single = {m: single_stats(byq, correct, m) for m in ALL_MODELS}
    for m in ALL_MODELS:
        s = single[m]
        tag = " *(closed)*" if m in CLOSED else ""
        out_lines.append(f"| {m}{tag} | {s['exact']:.1f}% | {s['meanJac']:.3f} | "
                         f"{s['answered']:.0f}% | ${s['cost_per_1k']:.2f} |")

    anchor = single[ANCHOR]

    # 2) mixtures  (compared against gpt-5.5)
    out_lines.append("\n### Mixtures of open-weight models\n")
    out_lines.append(f"| Mixture | rule | exact% | meanJac | answered% | $/1k Q "
                     f"| vs {ANCHOR} meanJac | $ vs {ANCHOR} |")
    out_lines.append("|---|---|--:|--:|--:|--:|--:|--:|")
    for pname, pool in POOLS.items():
        for rule in ["majority", "weighted", "union", "intersect"]:
            s = mixture_stats(byq, correct, pool, rule, weights)
            dmj = s["meanJac"] - anchor["meanJac"]
            cratio = s["cost_per_1k"] / anchor["cost_per_1k"] if anchor["cost_per_1k"] else float("nan")
            out_lines.append(f"| {pname} | {rule} | {s['exact']:.1f}% | {s['meanJac']:.3f} | "
                             f"{s['answered']:.0f}% | ${s['cost_per_1k']:.2f} | "
                             f"{dmj:+.3f} | {cratio:.2f}× |")

    # 3) threshold sweep (majority is a point on this curve)
    out_lines.append("\n### Threshold-k sweep (letter kept if ≥k members pick it)\n")
    for pname, pool in POOLS.items():
        row = [f"**{pname}**"]
        for k in range(1, len(pool) + 1):
            s = mixture_stats(byq, correct, pool, f"thresh-{k}", weights)
            row.append(f"k={k}: Jac {s['meanJac']:.3f}/ex {s['exact']:.0f}%")
        out_lines.append("- " + "  ·  ".join(row))

    # 4) oracle upper bounds
    out_lines.append("\n### Oracle upper bounds (NOT deployable — ceiling for a perfect per-question router)\n")
    out_lines.append("| Pool | any-member-exact % | best-member meanJac |")
    out_lines.append("|---|--:|--:|")
    for pname, pool in POOLS.items():
        o = oracle(byq, correct, pool)
        out_lines.append(f"| {pname} | {o['any_exact']:.1f}% | {o['best_jac']:.3f} |")

    # 5) verdict line
    out_lines.append("")
    best_mix = None
    for pname, pool in POOLS.items():
        for rule in ["majority", "weighted", "union", "intersect"]:
            s = mixture_stats(byq, correct, pool, rule, weights)
            cand = (s["meanJac"], pname, rule, s)
            if best_mix is None or cand[0] > best_mix[0]:
                best_mix = cand
    mj, pname, rule, s = best_mix
    verdict = ("MATCHES/BEATS" if mj >= anchor["meanJac"] - 1e-9 else "does NOT match")
    out_lines.append(f"> **Verdict ({name}):** best mixture = *{pname} · {rule}* at "
                     f"meanJac **{mj:.3f}** vs {ANCHOR} **{anchor['meanJac']:.3f}** "
                     f"→ {verdict}. Mixture answered {s['answered']:.0f}% "
                     f"(reliability), cost ${s['cost_per_1k']:.2f}/1k vs {ANCHOR} "
                     f"${anchor['cost_per_1k']:.2f}/1k.")
    return single


def main():
    h.load_env(REPO / ".env")
    h.load_prices()          # live Together prices + manual constants (from harness)

    lines = ["# Mixture-of-Open-Models Analysis",
             "\n_Offline aggregation of cached per-question answers "
             "(results/*_merged7.jsonl). No new API calls. Same Jaccard scoring "
             "as the harness. N=30/task — directional, not final._"]
    run_task("Malware Analysis", load_malware(), lines)
    run_task("Threat-Intel Reasoning", load_cti(), lines)

    out = "\n".join(lines)
    (HERE / "MIXTURE.md").write_text(out)
    print(out)
    print(f"\n[written to {HERE / 'MIXTURE.md'}]")


if __name__ == "__main__":
    main()
