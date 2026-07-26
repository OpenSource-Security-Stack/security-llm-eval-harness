"""PrimeVul (Ding et al., 2024) — binary vulnerability detection in C/C++.

Task: given a single C/C++ function, decide whether it is VULNERABLE (1) or NOT
vulnerable (0). PrimeVul deliberately pairs near-identical safe/vulnerable
functions (the *paired* slice) so surface cues — length, identifiers, comments —
don't leak the label; the model must reason about the actual defect. Scored with
Matthews correlation coefficient (MCC) over all binary predictions, the
imbalance-aware detection metric the paper reports (arXiv:2403.18624).

Dataset: HuggingFace mirror `starsofchance/PrimeVul` (PrimeVul-v0.1, MIT via the
upstream github.com/DLVulDet/PrimeVul repo). We use the PAIRED test slice
(`primevul_test_paired.jsonl`, 870 rows, perfectly balanced 435 vuln / 435 safe).
Schema per line: `func` (function source), `target` (1=vulnerable, 0=safe),
`idx` (stable id), plus project/cwe/cve metadata. Data is gitignored — fetch:

  mkdir -p benchmarks/primevul/data && curl -sL -o \
    benchmarks/primevul/data/primevul_test_paired.jsonl \
    https://huggingface.co/datasets/starsofchance/PrimeVul/resolve/main/primevul_test_paired.jsonl
"""
import json
import re

from harness import config
from harness.task import Task

DATA = config.REPO / "benchmarks/primevul/data/primevul_test_paired.jsonl"

# Cap the per-function source we show the model (very long functions blow up
# context/cost; the defect is almost always visible in the first ~8k chars).
_MAX_FUNC_CHARS = 8000


def load():
    if not DATA.exists():
        raise FileNotFoundError(
            f"{DATA} missing — fetch it:\n  mkdir -p {DATA.parent} && curl -sL -o {DATA} "
            "https://huggingface.co/datasets/starsofchance/PrimeVul/resolve/main/"
            "primevul_test_paired.jsonl")
    items = []
    for line in open(DATA):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if "func" not in r or "target" not in r:
            continue
        items.append(r)
    return items


def key(tc):
    return "primevul-" + str(tc["idx"])


def strata(tc):
    # Balance any deterministic subset across the two classes so a small N (e.g.
    # 60) always contains both vulnerable and safe functions.
    return "vuln" if int(tc["target"]) == 1 else "safe"


def gold(tc):
    return int(tc["target"])          # 1 = vulnerable, 0 = not vulnerable


def prompt(tc):
    func = tc["func"]
    if len(func) > _MAX_FUNC_CHARS:
        func = func[:_MAX_FUNC_CHARS] + "\n/* ...function truncated... */"
    return f"""You are a security code auditor. Below is a single C/C++ function. \
Decide whether it contains a security vulnerability.

```c
{func}
```

Is this function vulnerable? Think briefly if you need to, then ensure the last \
line of your response is exactly one word: "yes" if it is vulnerable, or "no" if \
it is not vulnerable."""


_YES = re.compile(r"\b(yes|vulnerable|vuln|insecure|unsafe)\b", re.IGNORECASE)
_NO = re.compile(r"\b(no|not\s+vulnerable|safe|secure|benign)\b", re.IGNORECASE)


def parse(text):
    """Map the model answer to 1 (vulnerable) or 0 (safe); None if unparseable.

    Preference order: an explicit 1/0 on the last non-empty line, then a yes/no
    keyword on the last line that carries one, then a whole-text fallback."""
    if not text:
        return None
    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]

    # 1) A bare 1/0 (or a last line that is just yes/no) wins.
    for line in reversed(lines):
        m = re.fullmatch(r"[\*\s\"'`>#-]*([01])[\.\*\s\"'`]*", line)
        if m:
            return int(m.group(1))
        low = re.sub(r"[^a-z]", "", line.lower())
        if low in ("yes", "vulnerable", "vuln", "insecure", "unsafe"):
            return 1
        if low in ("no", "notvulnerable", "safe", "secure", "benign"):
            return 0

    # 2) Last line that mentions yes/no (or a synonym); "not vulnerable" -> 0.
    for line in reversed(lines):
        yes, no = _YES.search(line), _NO.search(line)
        if no and (not yes or no.start() < yes.start()):
            return 0
        if yes:
            return 1

    # 3) Whole-text fallback: last standalone 1/0.
    hits = re.findall(r"\b([01])\b", text)
    if hits:
        return int(hits[-1])
    return None


def score(pred, gold_):
    """Per-item dict for the `mcc` aggregator. It reads d["pair"] = (pred, gold)
    with 0/1 labels; pred=None (a refusal / unparseable answer) is treated by the
    aggregator as the wrong class (predicted 0). We also surface a per-item 0/1
    `mcc` value (correct?) so single-item display paths have a number to show."""
    g = int(gold_)
    p = None if pred is None else int(pred)
    correct = (p is not None) and (p == g)
    return {"mcc": 1.0 if correct else 0.0, "pair": (p, g), "exact": correct}


def load_results():
    """Merge every primevul run in results/; last write wins per (model, qid)."""
    files = sorted(config.RESULTS.glob("primevul_n*_*.jsonl")) or \
        sorted(config.RESULTS.glob("primevul_*.jsonl"))
    if not files:
        raise FileNotFoundError("no primevul results yet — run: "
                                "python3 scripts/run.py --task primevul")
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


PRIMEVUL = Task(
    id="primevul", name="Vulnerability Detection", suite="PrimeVul",
    domain="codesec", domain_name="Code Security",
    benchmark_line="PrimeVul (paired test) · C/C++ function → vulnerable? · metric: MCC",
    metric={"id": "mcc", "direction": "higher", "aggregate": "mcc", "worst": 0.0},
    load=load, key=key, strata=strata, gold=gold,
    prompt=prompt, parse=parse, score=score,
    load_results=load_results,
)
