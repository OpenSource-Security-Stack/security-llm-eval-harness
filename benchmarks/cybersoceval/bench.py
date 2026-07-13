"""CyberSOCEval (Meta × CrowdStrike) — the first benchmark plugin.

Two tasks, both multi-select MCQ scored with Jaccard (PurpleLlama methodology):

  malware — leaf malware.sandbox_interpretation
            (Hybrid-Analysis detonation report + MCQ)
  cti     — leaf cti.ti_reasoning
            (CrowdStrike threat-intel report text + MCQ)

Dataset root comes from harness.config.data_dir() (a PurpleLlama checkout;
override with $SECROUTER_DATA_DIR). For `cti`, report text is extracted from
the local CrowdStrike PDFs with `pdftotext` and cached under cache/cti_txt/.
Only CrowdStrike-sourced questions are used (their PDFs ship locally).

Prompts, key/strata functions, and truncation are a faithful port of the
original monolith — outputs are byte-compatible with the cached results.
"""
import json
import re
import subprocess

from harness import config
from harness.metrics import extract_json, jaccard, normalize_letters
from harness.scoring import norm_gold
from harness.task import Task

SIGNATURE_DESCRIPTION_LEN = 50


def _mal_data():
    return config.data_dir() / "malware_analysis"


def _cti_data():
    return config.data_dir() / "threat_intel_reasoning"


# ---------------------------------------------------------------------------
# Shared parse + score (multi-select letters, Jaccard)
# ---------------------------------------------------------------------------
def parse_letters(text):
    """Model response -> list of letters, or None on parse failure."""
    obj = extract_json(text)
    if not obj or "correct_answers" not in obj:
        return None
    return normalize_letters(obj.get("correct_answers"))


def score_letters(pred, gold):
    j = jaccard(pred, [str(c).strip().upper()[:1] for c in gold])
    return {"jaccard": j, "exact": j == 1.0}


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
    return json.loads((_mal_data() / "questions.json").read_text())


def mal_key(tc):
    return tc["sha256"] + tc["question"]


def mal_strata(tc):
    return tc["attack"]


def mal_gold(tc):
    return [str(c).strip().upper()[:1] for c in tc["correct_options"]]


def mal_prompt(tc):
    with open(_mal_data() / "hybrid-analysis" / tc["attack"] / tc["sha256"]) as f:
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
    cache = config.CACHE / "cti_txt"
    cache.mkdir(parents=True, exist_ok=True)
    txt = cache / f"{report_id}.txt"
    if not txt.exists():
        pdf = _cti_data() / "crowdstrike-reports" / f"{report_id}.pdf"
        subprocess.run(["pdftotext", str(pdf), str(txt)], check=True)
    return txt.read_text(errors="ignore")


def cti_load():
    # only CrowdStrike-sourced questions -> local PDFs, no downloads
    return [q for q in json.loads((_cti_data() / "report_questions.json").read_text())
            if q.get("source") == "CrowdStrike"]


def cti_key(tc):
    return str(tc["question_id"])


def cti_strata(tc):
    return tc["report_id"]


def cti_gold(tc):
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


# ---------------------------------------------------------------------------
# Cached-results import (the merged v0 runs) -> canonical qids across models
# ---------------------------------------------------------------------------
def cti_load_results():
    recs = [json.loads(l) for l in open(config.RESULTS / "cti_n30_merged7.jsonl") if l.strip()]
    for r in recs:
        r["_qid"] = r["qkey"]                       # qkey is stable across models
    return recs


def mal_load_results():
    """Two schema families: older runs carry sha256/topic/difficulty; newer runs
    (gpt-5.5, opus) carry qkey == sha256+question. Map both to the canonical
    question id (= sha256+question) via the task's own deterministic subset."""
    from harness.runner import select_subset
    qs = mal_load()
    sub = select_subset(qs, 30, mal_key, mal_strata)
    canon = {mal_key(q) for q in sub}
    composite = {(q["sha256"], norm_gold(q["correct_options"]), q["topic"], q["difficulty"]): mal_key(q)
                 for q in sub}
    recs = [json.loads(l) for l in open(config.RESULTS / "malware_n30_merged7.jsonl") if l.strip()]
    for r in recs:
        if "qkey" in r and r["qkey"] in canon:      # newer family
            r["_qid"] = r["qkey"]
        else:                                       # older family
            r["_qid"] = composite[(r["sha256"], norm_gold(r["correct_options"]),
                                   r["topic"], r["difficulty"])]
    return recs


# ---------------------------------------------------------------------------
# The two Task objects (registered by benchmarks/__init__.py)
# ---------------------------------------------------------------------------
_SUITE = "CyberSOCEval (Meta × CrowdStrike)"

MALWARE = Task(
    id="malware", name="Malware Analysis", suite=_SUITE,
    benchmark_line=f"{_SUITE} · malware task · metric: Jaccard",
    metric={"id": "jaccard", "direction": "higher", "aggregate": "mean"},
    load=mal_load, key=mal_key, strata=mal_strata, gold=mal_gold,
    prompt=mal_prompt, parse=parse_letters, score=score_letters,
    load_results=mal_load_results,
)

CTI = Task(
    id="cti", name="Threat-Intel Reasoning", suite=_SUITE,
    benchmark_line=f"{_SUITE} · CTI task · metric: Jaccard",
    metric={"id": "jaccard", "direction": "higher", "aggregate": "mean"},
    load=cti_load, key=cti_key, strata=cti_strata, gold=cti_gold,
    prompt=cti_prompt, parse=parse_letters, score=score_letters,
    load_results=cti_load_results,
)
