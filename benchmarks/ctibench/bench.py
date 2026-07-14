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
    domain="vulnmgmt", domain_name="Vulnerability Management",
    benchmark_line="CTIBench-RCM · CVE root-cause → CWE · metric: accuracy",
    metric={"id": "accuracy", "direction": "higher", "aggregate": "mean"},
    load=load, key=key, strata=strata, gold=gold,
    prompt=prompt, parse=parse, score=score,
    combine=combine,
    load_results=load_results,
)


# ---------------------------------------------------------------------------
# CTIBench-VSP — CVE description -> CVSS v3.1 vector; scored as MAE over the
# base scores computed from predicted vs gold vectors (the paper's MAD metric).
# Models output a VECTOR (prompt: "final line ... only the CVSS v3 Vector
# String"); we compute both sides' base scores with the official v3.1 formula.
# ---------------------------------------------------------------------------
VSP_DATA = config.REPO / "benchmarks/ctibench/data/cti-vsp.tsv"

_VEC = re.compile(r"CVSS:3\.[01]/(?:[A-Z]{1,3}:[A-Z](?:/|\b))+", re.IGNORECASE)

# CVSS v3.1 base-score weights (first.org/cvss/v3.1/specification-document §7.4)
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},   # scope unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},   # scope changed
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    """CVSS v3.1 Roundup: smallest 1-decimal number >= x (spec Appendix A)."""
    i = round(x * 100000)
    return i / 100000 if i % 10000 == 0 else (i // 10000 + 1) / 10


def parse_cvss_vector(text):
    """Last CVSS:3.x vector in the text -> dict of base metrics, or None."""
    if not text:
        return None
    hits = _VEC.findall(text.upper())
    if not hits:
        return None
    m = dict(p.split(":") for p in hits[-1].split("/")[1:] if ":" in p)
    if not all(k in m for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A")):
        return None
    return m


def cvss31_base_score(m: dict) -> float:
    """CVSS v3.1 base score from a metric dict (first.org §7.1)."""
    changed = m["S"] == "C"
    iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    pr = _W["PR_C" if changed else "PR_U"][m["PR"]]
    expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    raw = 1.08 * (impact + expl) if changed else impact + expl
    return _roundup(min(raw, 10.0))


def vsp_load():
    if not VSP_DATA.exists():
        raise FileNotFoundError(
            f"{VSP_DATA} missing — fetch it:\n  curl -sL -o {VSP_DATA} "
            "https://huggingface.co/datasets/AI4Sec/cti-bench/resolve/main/cti-vsp.tsv")
    with open(VSP_DATA) as f:
        return list(csv.DictReader(f, delimiter="\t"))


def vsp_strata(tc):
    """Balance the subset across severity bands (low/med/high/crit)."""
    s = cvss31_base_score(parse_cvss_vector(tc["GT"]))
    return "crit" if s >= 9 else "high" if s >= 7 else "med" if s >= 4 else "low"


def vsp_parse(text):
    """Model response -> normalized vector string (the stored prediction)."""
    m = parse_cvss_vector(text)
    if m is None:
        return None
    return "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"))


def vsp_score(pred, gold_vec):
    """MAE between base scores of predicted vs gold vectors. Unparseable/None
    prediction -> worst error (10.0). exact = identical base metrics."""
    gm = parse_cvss_vector(gold_vec)
    pm = parse_cvss_vector(pred) if pred else None
    if pm is None:
        return {"mae": 10.0, "exact": False}
    err = abs(cvss31_base_score(pm) - cvss31_base_score(gm))
    return {"mae": round(err, 4), "exact": all(pm[k] == gm[k] for k in gm)}


def vsp_load_results():
    """Merge every cvss run in results/; last write wins per (model, qid)."""
    files = sorted(config.RESULTS.glob("cvss_n*_*.jsonl"))
    if not files:
        raise FileNotFoundError("no cvss results yet — run: python3 scripts/run.py --task cvss")
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


CVSS = Task(
    id="cvss", name="CVSS Severity Scoring", suite="CTIBench (VSP)",
    domain="vulnmgmt", domain_name="Vulnerability Management",
    benchmark_line="CTIBench-VSP · CVE description → CVSS v3.1 · metric: MAE (lower is better)",
    metric={"id": "mae", "direction": "lower", "aggregate": "mean"},
    load=vsp_load, key=key, strata=vsp_strata, gold=lambda tc: tc["GT"].strip().upper(),
    prompt=prompt, parse=vsp_parse, score=vsp_score,
    load_results=vsp_load_results,
)


# ---------------------------------------------------------------------------
# CTIBench-MCQ — CTI knowledge, 2,500 four-option questions.
# Prompt (verbatim): "The last line of your answer should contain only the
# single letter corresponding to the best option."
# ---------------------------------------------------------------------------
MCQ_DATA = config.REPO / "benchmarks/ctibench/data/cti-mcq.tsv"


def mcq_load():
    if not MCQ_DATA.exists():
        raise FileNotFoundError(
            f"{MCQ_DATA} missing — fetch it:\n  curl -sL -o {MCQ_DATA} "
            "https://huggingface.co/datasets/AI4Sec/cti-bench/resolve/main/cti-mcq.tsv")
    with open(MCQ_DATA) as f:
        return list(csv.DictReader(f, delimiter="\t"))


def mcq_key(tc):
    import hashlib
    return "mcq-" + hashlib.sha1(tc["Question"].encode()).hexdigest()[:12]


def mcq_strata(tc):
    return tc["GT"].strip().upper()      # balance across answer letters (A/B/C/D)


def mcq_parse(text):
    """Letter on the last non-empty line; fallback: last standalone A-D."""
    if not text:
        return None
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line:
            m = re.fullmatch(r"\**\(?([A-Da-d])\)?[\.\**]*", line)
            if m:
                return m.group(1).upper()
            break
    hits = re.findall(r"\b([A-D])\b", text)
    return hits[-1] if hits else None


MCQ = Task(
    id="cti_mcq", name="CTI Knowledge (MCQ)", suite="CTIBench (MCQ)",
    domain="cti", domain_name="Threat Intelligence",
    benchmark_line="CTIBench-MCQ · CTI knowledge, 4-option MCQ · metric: accuracy",
    metric={"id": "accuracy", "direction": "higher", "aggregate": "mean"},
    load=mcq_load, key=mcq_key, strata=mcq_strata,
    gold=lambda tc: tc["GT"].strip().upper(),
    prompt=prompt, parse=mcq_parse, score=score,
    load_results=lambda: _merge_results("cti_mcq"),
)


# ---------------------------------------------------------------------------
# CTIBench-ATE — extract MITRE ATT&CK technique IDs from malware/tool
# descriptions. 60 rows (FULL set — run with --n 60). Per-item F1 over
# technique-ID sets, sub-techniques normalized to parents (GT is parent-level).
# ---------------------------------------------------------------------------
ATE_DATA = config.REPO / "benchmarks/ctibench/data/cti-ate.tsv"

_TID = re.compile(r"T\d{4}(?:\.\d{3})?")


def ate_load():
    if not ATE_DATA.exists():
        raise FileNotFoundError(
            f"{ATE_DATA} missing — fetch it:\n  curl -sL -o {ATE_DATA} "
            "https://huggingface.co/datasets/AI4Sec/cti-bench/resolve/main/cti-ate.tsv")
    with open(ATE_DATA) as f:
        return list(csv.DictReader(f, delimiter="\t"))


def _tid_set(text):
    """Technique IDs in text, sub-techniques folded to parents (T1071.001->T1071)."""
    return sorted({t.split(".")[0] for t in _TID.findall(text or "")})


def ate_parse(text):
    """IDs from the last line that contains any; fallback: whole-text scan."""
    if not text:
        return None
    for line in reversed(text.strip().splitlines()):
        ids = _tid_set(line)
        if ids:
            return ids
    ids = _tid_set(text)
    return ids or None


def ate_score(pred, gold_):
    from harness.metrics import set_prf
    d = set_prf(_tid_set(",".join(pred)) if pred else [], _tid_set(gold_))
    return {"f1": d["f1"], "precision": d["precision"], "recall": d["recall"],
            "exact": d["fp"] == 0 and d["fn"] == 0}


ATE = Task(
    id="cti_ate", name="ATT&CK Technique Extraction", suite="CTIBench (ATE)",
    domain="cti", domain_name="Threat Intelligence",
    benchmark_line="CTIBench-ATE · text → MITRE technique IDs · metric: mean F1 · full set (60)",
    metric={"id": "f1", "direction": "higher", "aggregate": "mean"},
    load=ate_load, key=lambda tc: tc["URL"].rstrip("/").rsplit("/", 1)[-1],
    strata=lambda tc: tc["Platform"],
    gold=lambda tc: tc["GT"],
    prompt=prompt, parse=ate_parse, score=ate_score,
    load_results=lambda: _merge_results("cti_ate"),
)


def _merge_results(task_id):
    """Merge every run for task_id; last write wins per (model, qid)."""
    files = sorted(config.RESULTS.glob(f"{task_id}_n*_*.jsonl"))
    if not files:
        raise FileNotFoundError(f"no {task_id} results yet — run scripts/run.py --task {task_id}")
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
