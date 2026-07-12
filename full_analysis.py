#!/usr/bin/env python3
"""Generate a complete cross-leaf model comparison (quality x cost x reliability).

Reads the merged 5-model result files for both leaves, pulls live Together
prices + the OpenAI constant, recomputes cost uniformly from token counts, and
writes ANALYSIS.md.
"""
import json
import os
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

ROSTER = {  # friendly -> (provider, api_id, short descriptor)
    "opus-4.8":     ("anthropic", "claude-opus-4-8", "frontier closed (Anthropic)"),
    "gpt-5.5":      ("openai",   "gpt-5.5", "frontier closed (newer)"),
    "gpt-5.1":      ("openai",   "gpt-5.1", "frontier closed"),
    "glm-5.2":      ("together", "zai-org/GLM-5.2", "OSS reasoning (Zhipu)"),
    "minimax-m3":   ("together", "MiniMaxAI/MiniMax-M3", "OSS reasoning (MiniMax)"),
    "qwen3-235b":   ("together", "Qwen/Qwen3-235B-A22B-Instruct-2507-tput", "OSS MoE 235B (Alibaba)"),
    "gpt-oss-120b": ("together", "openai/gpt-oss-120b", "OSS 120B (OpenAI open-weights)"),
}
PRICES_OPENAI = {"gpt-5.1": {"input": 1.25, "output": 10.0},
                 "gpt-5.5": {"input": 1.25, "output": 10.0},          # PLACEHOLDER (=5.1)
                 "claude-opus-4-8": {"input": 15.0, "output": 75.0}}  # PLACEHOLDER (std Opus tier)
LEAVES = {"malware.sandbox_interpretation": "malware_n30_merged7",
          "cti.ti_reasoning": "cti_n30_merged7"}


def load_env(path):
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())


def prices():
    load_env(REPO / ".env")
    req = urllib.request.Request(
        "https://api.together.xyz/v1/models",
        headers={"Authorization": f"Bearer {os.environ.get('TOGETHER_API_KEY','')}",
                 "User-Agent": "security-router-eval/0.1"})
    tp = {}
    with urllib.request.urlopen(req, timeout=60) as r:
        for m in json.loads(r.read()):
            p = m.get("pricing") or {}
            tp[m["id"]] = {"input": p.get("input", 0), "output": p.get("output", 0)}
    out = {}
    for k, (prov, mid, _) in ROSTER.items():
        out[k] = tp.get(mid, {"input": 0, "output": 0}) if prov == "together" else PRICES_OPENAI[mid]
    return out


def stats(records, model, price):
    rs = [r for r in records if r["model"] == model]
    n = len(rs)
    exact = sum(r["answered_correctly"] == "true" for r in rs)
    mj = sum(r["score"] for r in rs) / n
    parse = 100 * sum(bool(r.get("parse_ok")) for r in rs) / n
    lat = sum(r["latency"] for r in rs) / n
    ptok = [r["prompt_tokens"] for r in rs if r.get("prompt_tokens")]
    ctok = [r["completion_tokens"] for r in rs if r.get("completion_tokens")]
    cost = sum((r.get("prompt_tokens") or 0) / 1e6 * price["input"] +
               (r.get("completion_tokens") or 0) / 1e6 * price["output"] for r in rs)
    return {
        "n": n, "exact_pct": 100 * exact / n, "meanJac": mj, "parse_pct": parse,
        "lat": lat, "in_tok": sum(ptok) / len(ptok) if ptok else 0,
        "out_tok": sum(ctok) / len(ctok) if ctok else 0,
        "cost_per_1k": cost / n * 1000, "cost_per_correct": (cost / exact) if exact else None,
        "exact": exact,
    }


def main():
    P = prices()
    data = {}  # leaf -> model -> stats
    for leaf, fname in LEAVES.items():
        recs = [json.loads(l) for l in open(HERE / "results" / f"{fname}.jsonl") if l.strip()]
        data[leaf] = {m: stats(recs, m, P[m]) for m in ROSTER}

    L = []
    L.append("# Security Router — v0 Model Comparison\n")
    L.append("**Leaves:** `malware.sandbox_interpretation`, `cti.ti_reasoning` (CyberSOCEval). "
             "**N = 30 questions/leaf**, 7 models. Scoring = Jaccard over multi-select letters "
             "(PurpleLlama methodology). CTI = CrowdStrike-only subset.\n")
    L.append("> ⚠️ **N=30 is a smoke sample** — meanJac gaps < ~0.05 and exact% ties are within noise. "
             "Read cost/latency/reliability as robust; treat fine quality ranks as provisional.\n")

    # 1. Model roster + price
    L.append("## 1. Models & pricing\n")
    L.append("| Model | Type | Provider | $/1M in | $/1M out |")
    L.append("|---|---|---|--:|--:|")
    for m, (prov, mid, desc) in ROSTER.items():
        L.append(f"| `{m}` | {desc} | {prov} | ${P[m]['input']:.2f} | ${P[m]['output']:.2f} |")
    L.append("\n_Together prices pulled live from its API; gpt-5.1 confirmed $1.25/$10 per 1M. "
             "⚠️ gpt-5.5 (= gpt-5.1) and opus-4.8 ($15/$75 std Opus tier) prices are PLACEHOLDERS — "
             "confirm their real rates to trust those $ columns._\n")

    # 2. Per-leaf tables
    for leaf in LEAVES:
        L.append(f"## 2. Benchmark — `{leaf}`\n")
        L.append("| Model | exact% | meanJac | parse✓ | latency | in tok/q | out tok/q | $/1k Q | $/correct |")
        L.append("|---|--:|--:|--:|--:|--:|--:|--:|--:|")
        rows = sorted(data[leaf].items(), key=lambda kv: -kv[1]["meanJac"])
        for m, s in rows:
            cpc = "n/a" if s["cost_per_correct"] is None else f"${s['cost_per_correct']:.4f}"
            L.append(f"| `{m}` | {s['exact_pct']:.1f}% | {s['meanJac']:.3f} | {s['parse_pct']:.0f}% | "
                     f"{s['lat']:.1f}s | {s['in_tok']:.0f} | {s['out_tok']:.0f} | "
                     f"${s['cost_per_1k']:.2f} | {cpc} |")
        L.append("")

    # 3. Cross-leaf quality
    L.append("## 3. Cross-leaf quality (meanJac) & the reshuffle\n")
    L.append("| Model | malware | CTI | avg | malware rank | CTI rank |")
    L.append("|---|--:|--:|--:|:-:|:-:|")
    ml, ct = list(LEAVES)[0], list(LEAVES)[1]
    mrank = {m: i + 1 for i, (m, _) in enumerate(sorted(data[ml].items(), key=lambda kv: -kv[1]["meanJac"]))}
    crank = {m: i + 1 for i, (m, _) in enumerate(sorted(data[ct].items(), key=lambda kv: -kv[1]["meanJac"]))}
    for m in sorted(ROSTER, key=lambda x: -(data[ml][x]["meanJac"] + data[ct][x]["meanJac"]) / 2):
        a, b = data[ml][m]["meanJac"], data[ct][m]["meanJac"]
        L.append(f"| `{m}` | {a:.3f} | {b:.3f} | {(a+b)/2:.3f} | {mrank[m]} | {crank[m]} |")
    L.append("")

    # 4. Cost-efficiency
    L.append("## 4. Cost-efficiency ($/correct answer)\n")
    L.append("| Model | malware $/correct | CTI $/correct |")
    L.append("|---|--:|--:|")
    for m in ROSTER:
        a = data[ml][m]["cost_per_correct"]; b = data[ct][m]["cost_per_correct"]
        L.append(f"| `{m}` | {'n/a' if a is None else f'${a:.4f}'} | {'n/a' if b is None else f'${b:.4f}'} |")
    L.append("")

    out = "\n".join(L)
    (HERE / "ANALYSIS.md").write_text(out)
    print(out)
    print(f"\n\n[written to {HERE / 'ANALYSIS.md'}]")


if __name__ == "__main__":
    main()
