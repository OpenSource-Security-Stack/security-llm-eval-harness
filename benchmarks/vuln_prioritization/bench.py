"""Vulnerability Prioritization — KEV/EPSS ranking (CISA × FIRST.org).

Each "question" is a batch of ~15 CVEs (a mix of genuinely dangerous and
low-risk ones). The model must RANK them most-urgent-to-least. We grade the
ranking with nDCG@10 where each CVE's relevance gain is its EPSS exploitation
probability (0-1), and any CVE on the CISA KEV list gets a full gain of 1.0.
A high score means the model floated the truly dangerous CVEs to the top.

Why this leaf matters: triage/patch prioritization is the daily SOC/vuln-mgmt
grind. KEV = "known exploited in the wild" (must-patch); EPSS = predicted
exploitation probability. Together they are the field-standard prioritization
signal, so a model that can't reproduce them from CVE text is a poor router
target for this task.

Data is a FROZEN snapshot (data/questions.json), built once by build_data.py
from three free sources. The dir is gitignored — rebuild with:
    python3 benchmarks/vuln_prioritization/build_data.py

Credit: KEV = CC0 (CISA). EPSS = free with attribution (FIRST.org). NVD (public
domain) supplies descriptions for low-EPSS distractors. Paper: arXiv:2302.14172.
"""
import json
import re

from harness import config
from harness.metrics import ndcg_at_k
from harness.task import Task

DATA = config.REPO / "benchmarks/vuln_prioritization/data/questions.json"

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def load():
    if not DATA.exists():
        raise FileNotFoundError(
            f"{DATA} missing — build the frozen snapshot:\n  "
            "python3 benchmarks/vuln_prioritization/build_data.py")
    blob = json.loads(DATA.read_text())
    return blob["questions"]


def key(item):
    return item["qid"]


def strata(item):
    """Balance any subset by how many KEV CVEs the batch contains."""
    return f"kev{sum(1 for c in item['cves'] if c['kev'])}"


def gold(item):
    """Gold carries the gains dict (cve -> relevance) the scorer needs."""
    return item["gains"]


def prompt(item):
    lines = [
        "You are a vulnerability-management analyst doing patch triage.",
        "Below are CVEs discovered in your environment. Rank them from MOST "
        "urgent to patch (most likely to be exploited / already exploited in "
        "the wild) to LEAST urgent.",
        "",
        "CVEs (in no particular order):",
    ]
    for c in item["cves"]:
        desc = " ".join((c["desc"] or "").split())
        if len(desc) > 500:
            desc = desc[:500].rstrip() + "…"
        lines.append(f"- {c['cve']}: {desc}")
    lines += [
        "",
        "Return ONLY the ranked list of CVE IDs, one per line, most urgent "
        "first, numbered 1 to {}. Do not include descriptions or commentary."
        .format(len(item["cves"])),
    ]
    return "\n".join(lines)


def parse(raw):
    """Ordered list of CVE IDs from the model's text.

    Robust to numbered lists, bullets, JSON arrays, inline prose. Preserves the
    order of first appearance and dedupes (keeps first occurrence). None if no
    CVE id is found (treated as a refusal by the scorer)."""
    if not raw:
        return None
    ids = [m.group(0).upper() for m in _CVE.finditer(raw)]
    if not ids:
        return None
    seen, ordered = set(), []
    for cid in ids:
        if cid not in seen:
            seen.add(cid)
            ordered.append(cid)
    return ordered


def score(pred, gold_):
    """nDCG@10 of the predicted ranking against the EPSS/KEV gains.
    Refusal / unparseable (pred None) -> worst score 0.0."""
    if not pred:
        return {"ndcg": 0.0}
    return {"ndcg": ndcg_at_k(pred, gold_, k=10)}


def load_results():
    """Merge every vuln_prio run in results/; last write wins per (model, qid)."""
    files = sorted(config.RESULTS.glob("vuln_prio_n*_*.jsonl"))
    if not files:
        raise FileNotFoundError("no vuln_prio results yet — run: "
                                "python3 scripts/run.py --task vuln_prio")
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


VULN_PRIO = Task(
    id="vuln_prio", name="Vulnerability Prioritization",
    suite="KEV/EPSS (CISA × FIRST)",
    domain="vulnmgmt", domain_name="Vulnerability Management",
    benchmark_line="CISA KEV × FIRST EPSS · rank a CVE batch by exploitation "
                   "risk · metric: nDCG@10 (gain = EPSS, KEV = 1.0)",
    metric={"id": "ndcg", "direction": "higher", "aggregate": "mean", "worst": 0.0},
    load=load, key=key, strata=strata, gold=gold,
    prompt=prompt, parse=parse, score=score,
    load_results=load_results,
)
