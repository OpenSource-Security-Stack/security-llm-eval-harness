#!/usr/bin/env python3
"""
CyberSOCEval runner — Security Router v0 eval slice.

Runs a CyberSOCEval task against a fixed model roster, scored with the SAME
methodology as PurpleLlama (Jaccard similarity over multi-select letters,
exact = Jaccard==1.0). Two tasks:

  --task malware  -> leaf malware.sandbox_interpretation
                     (Hybrid-Analysis detonation report + MCQ)
  --task cti      -> leaf cti.ti_reasoning
                     (CrowdStrike threat-intel report text + MCQ)

For `cti`, report text is extracted from the local CrowdStrike PDFs with
`pdftotext` and cached under evals/cache/cti_txt/. Only CrowdStrike-sourced
questions are used (their PDFs ship locally — no downloads).

OSS models run on Together; GPT models on OpenAI (both OpenAI-compatible
/v1/chat/completions). Keys read from security-router/.env (never printed).
Cost uses live Together prices + an editable OpenAI constant (see PRICES).

Usage:
  python3 run_cybersoceval.py --task malware --n 30
  python3 run_cybersoceval.py --task cti --n 30 --models gpt-5.1 qwen3-235b
"""
import argparse
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
from collections import Counter, defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
ROOT = REPO.parent
CRWD = ROOT / "PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta"
MAL_DATA = CRWD / "malware_analysis"
CTI_DATA = CRWD / "threat_intel_reasoning"
RESULTS = HERE / "results"
CACHE = HERE / "cache" / "cti_txt"

SIGNATURE_DESCRIPTION_LEN = 50

# ---------------------------------------------------------------------------
# Model roster: friendly -> (provider, api_id)
# ---------------------------------------------------------------------------
ROSTER = {
    "gpt-5.1":      ("openai",    "gpt-5.1"),
    "gpt-5.5":      ("openai",    "gpt-5.5"),
    "opus-4.8":     ("anthropic", "claude-opus-4-8"),
    "minimax-m3":   ("together",  "MiniMaxAI/MiniMax-M3"),
    "qwen3-235b":   ("together",  "Qwen/Qwen3-235B-A22B-Instruct-2507-tput"),
    "glm-5.2":      ("together",  "zai-org/GLM-5.2"),
    "gpt-oss-120b": ("together",  "openai/gpt-oss-120b"),
}

PROVIDERS = {
    "openai":    ("https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY"),
    "together":  ("https://api.together.xyz/v1/chat/completions", "TOGETHER_API_KEY"),
    "anthropic": ("https://api.anthropic.com/v1/messages", "ANTHROPIC_API_KEY"),
}

# Together prices are fetched live from /v1/models at startup.
# OpenAI/Anthropic don't expose pricing via API -> set here. USD per 1M tokens.
PRICES_MANUAL = {
    "gpt-5.1":         {"input": 1.25, "output": 10.0},   # confirmed by user
    "gpt-5.5":         {"input": 1.25, "output": 10.0},   # PLACEHOLDER (= gpt-5.1); confirm
    "claude-opus-4-8": {"input": 15.0, "output": 75.0},   # PLACEHOLDER (std Opus tier); confirm
}
PRICES = {}  # filled at runtime: model_key -> {"input":$/1M, "output":$/1M}


# ---------------------------------------------------------------------------
# .env loader
# ---------------------------------------------------------------------------
def load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())


def load_prices() -> None:
    """Populate PRICES for every roster model: live Together + OpenAI constant."""
    url, keyname = PROVIDERS["together"]
    req = urllib.request.Request(
        "https://api.together.xyz/v1/models",
        headers={"Authorization": f"Bearer {os.environ.get(keyname,'')}",
                 "User-Agent": "security-router-eval/0.1"},
    )
    together = {}
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            for m in json.loads(r.read()):
                p = m.get("pricing") or {}
                together[m["id"]] = {"input": p.get("input", 0), "output": p.get("output", 0)}
    except Exception as e:
        print(f"warn: could not fetch Together prices ({e}); costs may be 0")
    for key, (prov, mid) in ROSTER.items():
        if prov == "together":
            PRICES[key] = together.get(mid, {"input": 0, "output": 0})
        else:
            PRICES[key] = PRICES_MANUAL.get(mid, {"input": 0, "output": 0})


def cost_usd(model_key: str, prompt_tok, completion_tok) -> float:
    p = PRICES.get(model_key, {"input": 0, "output": 0})
    pt = (prompt_tok or 0) / 1e6 * p["input"]
    ct = (completion_tok or 0) / 1e6 * p["output"]
    return pt + ct


# ---------------------------------------------------------------------------
# Malware task — faithful port of malware_analysis.py
# ---------------------------------------------------------------------------
def _remove_hashes(obj):
    pat = r"[0-9a-f]{32,}"
    if isinstance(obj, dict):
        for k, val in list(obj.items()):
            if isinstance(val, str):
                obj[k] = re.sub(pat, "hash", val)
            elif isinstance(val, (dict, list)):
                _remove_hashes(val)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, str):
                obj[i] = re.sub(pat, "hash", item)
            elif isinstance(item, (dict, list)):
                _remove_hashes(item)
    return obj


MAL_KEYS = ["size", "type", "submit_name", "sha256", "av_detect", "vx_family",
            "threat_score", "threat_level", "verdict", "certificates_validation_message",
            "total_processes", "total_signatures", "file_metadata", "processes",
            "mitre_attcks", "network_mode", "signatures"]


def _truncate_report(report: dict) -> dict:
    out = {k: report[k] for k in MAL_KEYS if k in report}
    out = _remove_hashes(out)
    sigs = []
    for s in out.get("signatures", []):
        if "description" in s:
            s["description"] = s["description"][:SIGNATURE_DESCRIPTION_LEN]
        sigs.append(s)
    out["signatures"] = sigs
    out["mitre_attcks"] = [{k: a[k] for k in ["tactic", "technique", "attck_id"] if k in a}
                           for a in out.get("mitre_attcks", [])]
    return out


def mal_load():
    return json.loads((MAL_DATA / "questions.json").read_text())


def mal_key(tc):
    return tc["sha256"] + tc["question"]


def mal_strata(tc):
    return tc["attack"]


def mal_correct(tc):
    return [str(c).strip().upper()[:1] for c in tc["correct_options"]]


def mal_prompt(tc):
    with open(MAL_DATA / "hybrid-analysis" / tc["attack"] / tc["sha256"]) as f:
        report = _truncate_report(json.load(f))
    return f"""Given this detonation report: {report}.

        Answer the following multi-choice question: {tc['question']}.

        Options: {tc['options']}.

        You need to return the list of correct answers. Respond in a json with the following structure:
        {{
            "correct_answers": string[] // The list of the letters corresponding to the correct answers, just the letters
        }}
        """


# ---------------------------------------------------------------------------
# CTI task — faithful port of threat_intel_reasoning_benchmark.py (text modality)
# ---------------------------------------------------------------------------
def _ensure_cti_text(report_id: str) -> str:
    """Extract report text from the local CrowdStrike PDF (cached)."""
    CACHE.mkdir(parents=True, exist_ok=True)
    txt = CACHE / f"{report_id}.txt"
    if not txt.exists():
        pdf = CTI_DATA / "crowdstrike-reports" / f"{report_id}.pdf"
        subprocess.run(["pdftotext", str(pdf), str(txt)], check=True)
    return txt.read_text(errors="ignore")


def cti_load():
    # only CrowdStrike-sourced questions -> local PDFs, no downloads
    return [q for q in json.loads((CTI_DATA / "report_questions.json").read_text())
            if q.get("source") == "CrowdStrike"]


def cti_key(tc):
    return str(tc["question_id"])


def cti_strata(tc):
    return tc["report_id"]


def cti_correct(tc):
    return [str(c).strip().upper()[:1] for c in tc["correct_answer"]]


def cti_prompt(tc):
    context = _ensure_cti_text(tc["report_id"])
    return f"""
            {context}


        Given the context, answer the following question: {tc['question_text']}. Options: {tc['options']}.
        You need to return the list of correct answers. it is possible that there are multiple correct answers. or a single correct answer.
        Respond in a JSON with the following structure:
        {{correct_answers: string[] //The list of the letters corresponding to the correct answers, just the letters}}
        surround the JSON response with <json_object></json_object> tags and make sure to return the JSON response only.
        Example response:
        <json_object>{{"correct_answers": ["A", "C", "D"]}}</json_object>.

        """


TASKS = {
    "malware": {"leaf": "malware.sandbox_interpretation", "load": mal_load,
                "key": mal_key, "strata": mal_strata, "correct": mal_correct, "prompt": mal_prompt},
    "cti":     {"leaf": "cti.ti_reasoning", "load": cti_load,
                "key": cti_key, "strata": cti_strata, "correct": cti_correct, "prompt": cti_prompt},
}


# ---------------------------------------------------------------------------
# Scoring — faithful port
# ---------------------------------------------------------------------------
def extract_json(text: str):
    """Last brace-balanced JSON object containing 'correct_answers'.

    Handles reasoning traces (<think>) and <json_object> wrappers."""
    if not text:
        return None
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    candidates, depth, start = [], 0, None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    candidates.append(text[start:i + 1])
    best = best_with_key = None
    for c in candidates:
        try:
            obj = json.loads(c)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            best = obj
            if "correct_answers" in obj:
                best_with_key = obj
    return best_with_key if best_with_key is not None else best


def jaccard(a, b) -> float:
    sa, sb = set(a), set(b)
    inter = len(sa & sb)
    union = len(sa) + len(sb) - inter
    return inter / union if union > 0 else 0.0


def normalize_letters(vals) -> list:
    out = []
    if isinstance(vals, str):
        vals = [vals]
    for v in vals or []:
        m = re.search(r"[A-Za-z]", str(v))
        if m:
            out.append(m.group(0).upper())
    return out


# ---------------------------------------------------------------------------
# Model call
# ---------------------------------------------------------------------------
def call_model(provider: str, model_id: str, prompt: str, timeout: int = 180):
    url, keyname = PROVIDERS[provider]
    key = os.environ.get(keyname, "")
    if provider == "anthropic":
        # Anthropic Messages API: different endpoint/headers/body/response shape.
        # NB: temperature is deprecated/rejected for opus-4.8 — omit it.
        body = {"model": model_id, "max_tokens": 8192,
                "messages": [{"role": "user", "content": prompt}]}
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01",
                   "content-type": "application/json", "User-Agent": "security-router-eval/0.1"}
    else:  # openai-compatible (openai, together)
        body = {"model": model_id, "messages": [{"role": "user", "content": prompt}]}
        if provider == "together":
            body["temperature"] = 0
            body["max_tokens"] = 24576
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                   "User-Agent": "security-router-eval/0.1"}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    t0 = time.time()
    payload, last_err = None, None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                payload = json.loads(r.read())
            break
        except urllib.error.HTTPError as e:
            last_err = f"HTTP {e.code}: {e.read().decode()[:300]}"
            if e.code not in (429, 500, 502, 503, 504):
                return {"error": last_err, "latency": time.time() - t0}
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
        time.sleep(2 * (attempt + 1))
    if payload is None:
        return {"error": last_err, "latency": time.time() - t0}
    latency = time.time() - t0
    try:
        if provider == "anthropic":
            content = "".join(b.get("text", "") for b in payload["content"] if b.get("type") == "text")
            u = payload.get("usage", {})
            prompt_tok, completion_tok = u.get("input_tokens"), u.get("output_tokens")
        else:
            content = payload["choices"][0]["message"]["content"]
            u = payload.get("usage", {})
            prompt_tok, completion_tok = u.get("prompt_tokens"), u.get("completion_tokens")
    except (KeyError, IndexError):
        return {"error": f"bad response shape: {str(payload)[:300]}", "latency": latency}
    return {"content": content, "latency": latency,
            "prompt_tokens": prompt_tok, "completion_tokens": completion_tok}


# ---------------------------------------------------------------------------
# Deterministic stratified subset
# ---------------------------------------------------------------------------
def select_subset(questions, n, key_fn, strata_fn):
    by = defaultdict(list)
    for q in sorted(questions, key=lambda x: (strata_fn(x), key_fn(x))):
        by[strata_fn(q)].append(q)
    strata = sorted(by)
    picked, i = [], 0
    while len(picked) < n:
        added = False
        for s in strata:
            if i < len(by[s]):
                picked.append(by[s][i]); added = True
                if len(picked) == n:
                    break
        if not added:
            break
        i += 1
    return picked


# ---------------------------------------------------------------------------
# Score one (model, test-case)
# ---------------------------------------------------------------------------
def score_one(model_key, task, tc, prompt):
    provider, model_id = ROSTER[model_key]
    res = call_model(provider, model_id, prompt)
    correct = task["correct"](tc)
    rec = {"model": model_key, "qkey": task["key"](tc), "strata": task["strata"](tc),
           "correct_options": correct, "latency": round(res.get("latency", 0), 2),
           "prompt_tokens": res.get("prompt_tokens"),
           "completion_tokens": res.get("completion_tokens")}
    rec["cost_usd"] = round(cost_usd(model_key, rec["prompt_tokens"], rec["completion_tokens"]), 6)
    if "error" in res:
        rec.update({"error": res["error"], "parse_ok": False, "score": 0.0,
                    "answered_correctly": "query error"})
        return rec
    parsed = extract_json(res["content"])
    if not parsed or "correct_answers" not in parsed:
        rec.update({"raw": res["content"][:200], "parse_ok": False, "score": 0.0,
                    "answered_correctly": "parsing error"})
        return rec
    answers = normalize_letters(parsed.get("correct_answers"))
    score = jaccard(answers, correct)
    rec.update({"model_answers": answers, "parse_ok": True, "score": round(score, 4),
                "answered_correctly": "true" if score == 1.0 else "false"})
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", choices=list(TASKS), default="malware")
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--models", nargs="*", default=list(ROSTER))
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    load_env(REPO / ".env")
    load_prices()
    for mk in args.models:
        if mk not in ROSTER:
            sys.exit(f"unknown model '{mk}'. known: {list(ROSTER)}")

    task = TASKS[args.task]
    questions = task["load"]()
    subset = select_subset(questions, args.n, task["key"], task["strata"])
    print(f"Task: {args.task}  ->  leaf {task['leaf']}")
    print(f"Questions: {len(subset)}  |  by strata: {dict(Counter(task['strata'](q) for q in subset))}")
    print(f"Models: {args.models}")
    print(f"Prices ($/1M in/out): " +
          ", ".join(f"{m}={PRICES[m]['input']}/{PRICES[m]['output']}" for m in args.models) + "\n")

    prompts = {task["key"](q): task["prompt"](q) for q in subset}
    jobs = [(mk, tc, prompts[task["key"](tc)]) for mk in args.models for tc in subset]

    records, done = [], 0
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(score_one, mk, task, tc, p): mk for mk, tc, p in jobs}
        for fut in cf.as_completed(futs):
            records.append(fut.result()); done += 1
            print(f"\r  {done}/{len(jobs)} calls done", end="", flush=True)
    print()

    ts = int(time.time())
    out = RESULTS / f"{args.task}_n{args.n}_{ts}.jsonl"
    with open(out, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    # summary
    print("\n" + "=" * 92)
    print(f"{'model':<14}{'exact%':>8}{'meanJac':>9}{'parse✓':>8}{'lat(s)':>8}{'ctok/q':>8}"
          f"{'$/1kQ':>9}{'$/correct':>11}")
    print("-" * 92)
    summary = []
    for mk in args.models:
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
    (RESULTS / f"summary_{args.task}_n{args.n}_{ts}.json").write_text(json.dumps(summary, indent=2))
    print(f"\nRaw:     {out}")
    print(f"Summary: {RESULTS / f'summary_{args.task}_n{args.n}_{ts}.json'}")


if __name__ == "__main__":
    main()
