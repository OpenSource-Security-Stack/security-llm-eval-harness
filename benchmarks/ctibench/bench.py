"""CTIBench-RCM (Alam et al., 2024) — CVE -> CWE root-cause mapping.

Given an NVD CVE description, name the CWE weakness class that is the root
cause. Single-label, scored with exact-match accuracy. This is the leaf where
a fine-tuned 8B (Foundation-Sec-8B-Reasoning, 75.3%) beats default-prompted
GPT-5 (72.1%) — a core routing datapoint.

Dataset: huggingface.co/datasets/AI4Sec/cti-bench (cti-rcm.tsv, 1000 rows,
columns URL / Description / Prompt / GT). The `Prompt` column is the paper's
canonical prompt and is used VERBATIM ("Ensure the last line of your response
contains only the CWE ID"). Data is gitignored — fetch with:

  mkdir -p benchmarks/ctibench/data && curl -sL -o benchmarks/ctibench/data/cti-rcm.tsv \
    https://huggingface.co/datasets/AI4Sec/cti-bench/resolve/main/cti-rcm.tsv
"""
import csv
import json
import re
from collections import Counter

from harness import config
from harness.task import Task

DATA = config.REPO / "benchmarks/ctibench/data/cti-rcm.tsv"

_CVE = re.compile(r"CVE-\d{4}-\d+")
_CWE = re.compile(r"CWE-\d+", re.IGNORECASE)


def load():
    if not DATA.exists():
        raise FileNotFoundError(
            f"{DATA} missing — fetch it:\n  curl -sL -o {DATA} "
            "https://huggingface.co/datasets/AI4Sec/cti-bench/resolve/main/cti-rcm.tsv")
    with open(DATA) as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    return rows


def key(tc):
    return _CVE.search(tc["URL"]).group(0)


def strata(tc):
    return tc["GT"]            # balance the subset across CWE classes


def gold(tc):
    return tc["GT"].strip().upper()


def prompt(tc):
    return tc["Prompt"]        # canonical CTIBench prompt, verbatim


def parse(text):
    """Last CWE-### mentioned (the prompt demands the last line be the CWE ID)."""
    hits = _CWE.findall(text or "")
    return hits[-1].upper() if hits else None


def score(pred, gold_):
    ok = str(pred).strip().upper() == str(gold_).strip().upper()
    return {"accuracy": 1.0 if ok else 0.0, "exact": ok}


def combine(members, rule, weights=None):
    """Single-label pool merge: plurality vote ('majority') or weight-sum
    ('weighted'). Ties break to the alphabetically-first label (deterministic)."""
    voting = [m for m in members if m["answered"]]
    if not voting:
        return None, False
    if rule == "weighted" and weights:
        tally = Counter()
        for m in voting:
            tally[str(m["pred"]).strip().upper()] += weights[m["_model"]]
    else:                       # majority == plurality for single-label
        tally = Counter(str(m["pred"]).strip().upper() for m in voting)
    top = max(tally.values())
    return sorted(L for L, c in tally.items() if c == top)[0], True


def load_results():
    """Merge every cve_cwe run in results/; last write wins per (model, qid)."""
    files = sorted(config.RESULTS.glob("cve_cwe_n*_*.jsonl"))
    if not files:
        raise FileNotFoundError("no cve_cwe results yet — run: "
                                "python3 scripts/run.py --task cve_cwe")
    merged = {}
    for path in files:
        for line in open(path):
            if line.strip():
                r = json.loads(line)
                merged[(r["model"], r["qkey"])] = r
    recs = list(merged.values())
    for r in recs:
        r["_qid"] = r["qkey"]
    return recs


CVE_CWE = Task(
    id="cve_cwe", name="CVE→CWE Mapping", suite="CTIBench (RCM)",
    benchmark_line="CTIBench-RCM · CVE root-cause → CWE · metric: accuracy",
    metric={"id": "accuracy", "direction": "higher", "aggregate": "mean"},
    load=load, key=key, strata=strata, gold=gold,
    prompt=prompt, parse=parse, score=score,
    combine=combine,
    load_results=load_results,
)
