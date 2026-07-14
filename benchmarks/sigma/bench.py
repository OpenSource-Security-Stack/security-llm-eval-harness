"""Sigma→ATT&CK — detection-engineering benchmark derived from SigmaHQ/sigma.

Task: given a Sigma detection rule with its ATT&CK tags stripped, name the
MITRE ATT&CK technique IDs the rule detects. Ground truth = the stripped
`attack.tXXXX(.XXX)` tags; scored as per-item F1 over technique-ID sets with
sub-techniques folded to parents (consistent with our CTIBench-ATE leaf).

Source & credit: the SigmaHQ rule corpus (github.com/SigmaHQ/sigma, Detection
Rule License 1.1) — ~3k rules with technique tags. The prompt is ours (no
canonical prompt exists; the benchmark idea was popularized by a results-only
leaderboard that published no artifact, so we reconstruct from the original
source). Data is gitignored — fetch with:

  curl -sL https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master \
    | tar -xz -C benchmarks/sigma/data --strip-components=1
"""
import json
import re

from harness import config
from harness.metrics import set_prf
from harness.task import Task

RULES_DIR = config.REPO / "benchmarks/sigma/data/rules"

_TID = re.compile(r"T\d{4}(?:\.\d{3})?")
_ATTACK_TAG = re.compile(r"^\s*-\s*attack\.\S+\s*$", re.IGNORECASE)
_ATTACK_TID = re.compile(r"^\s*-\s*attack\.(t\d{4}(?:\.\d{3})?)\s*$", re.IGNORECASE)
_RULE_ID = re.compile(r"^id:\s*([0-9a-fA-F-]{8,})\s*$", re.MULTILINE)
_PRODUCT = re.compile(r"^\s+(?:product|category):\s*(\S+)", re.MULTILINE)

_CACHE = None


def load():
    """Walk the rule corpus once; keep rules that carry >= 1 technique tag."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    if not RULES_DIR.exists():
        raise FileNotFoundError(
            f"{RULES_DIR} missing — fetch SigmaHQ rules:\n"
            "  curl -sL https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master"
            " | tar -xz -C benchmarks/sigma/data --strip-components=1")
    items = []
    for path in sorted(RULES_DIR.rglob("*.yml")):
        text = path.read_text(errors="ignore")
        tids = [m.group(1).upper() for line in text.splitlines()
                if (m := _ATTACK_TID.match(line))]
        if not tids:
            continue
        rid = _RULE_ID.search(text)
        stripped_lines = [l for l in text.splitlines() if not _ATTACK_TAG.match(l)]
        # drop a now-empty tags: block header
        out = []
        for i, l in enumerate(stripped_lines):
            if l.strip() == "tags:" and (i + 1 >= len(stripped_lines)
                                         or not stripped_lines[i + 1].lstrip().startswith("-")):
                continue
            out.append(l)
        prod = _PRODUCT.search(text)
        items.append({"rule_id": rid.group(1) if rid else path.stem,
                      "rule": "\n".join(out),
                      "techniques": sorted(set(tids)),
                      "logsource": (prod.group(1) if prod else "unknown")})
    _CACHE = items
    return items


def key(tc):
    return tc["rule_id"]


def strata(tc):
    return tc["logsource"]      # diversity across products/categories


def gold(tc):
    return ", ".join(tc["techniques"])


def prompt(tc):
    return f"""You are a detection engineer. Below is a Sigma detection rule with its MITRE ATT&CK tags removed. Based on what the rule detects, identify the MITRE ATT&CK technique ID(s) it covers.

Sigma rule:
```yaml
{tc['rule']}
```

Provide brief reasoning, then ensure the last line of your response contains ONLY the comma-separated MITRE technique ID(s), e.g.: T1071, T1102
"""


def _fold(ids):
    """Sub-techniques -> parent techniques (T1071.001 -> T1071)."""
    return sorted({t.split(".")[0] for t in ids})


def parse(text):
    """IDs from the last line that contains any; fallback: whole-text scan."""
    if not text:
        return None
    for line in reversed(text.strip().splitlines()):
        ids = sorted({t.upper() for t in _TID.findall(line)})
        if ids:
            return ids
    ids = sorted({t.upper() for t in _TID.findall(text)})
    return ids or None


def score(pred, gold_):
    d = set_prf(_fold(pred or []), _fold(_TID.findall(gold_)))
    return {"f1": d["f1"], "precision": d["precision"], "recall": d["recall"],
            "exact": d["fp"] == 0 and d["fn"] == 0}


def load_results():
    files = sorted(config.RESULTS.glob("sigma_attack_n*_*.jsonl"))
    if not files:
        raise FileNotFoundError("no sigma_attack results yet — run scripts/run.py --task sigma_attack")
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


SIGMA_ATTACK = Task(
    id="sigma_attack", name="Sigma Rule → ATT&CK", suite="SigmaHQ-derived (DRL 1.1)",
    domain="deteng", domain_name="Detection Engineering",
    benchmark_line="SigmaHQ rules (tags stripped) → technique IDs · metric: mean F1",
    metric={"id": "f1", "direction": "higher", "aggregate": "mean"},
    load=load, key=key, strata=strata, gold=gold,
    prompt=prompt, parse=parse, score=score,
    load_results=load_results,
)
