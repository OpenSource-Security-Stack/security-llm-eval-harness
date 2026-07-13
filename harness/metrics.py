"""Pure metric + parsing helpers. No I/O, no state — safe for any benchmark.

Two layers:
  per-item scorers — (pred, gold) -> dict. Called with pred=None for
    unanswered items, and must return that metric's WORST value for them
    (0 for higher-is-better; an explicit `worst` for lower-is-better like MAE
    — never 0, which would reward refusals).
  AGGREGATORS — turn the full list of per-item dicts into the domain score.
    "mean" covers most metrics; macro_f1 / micro_f1 / mcc are corpus-level
    (computed over all (pred, gold) pairs at once, NOT averaged per item).

Not implemented here (need machinery we don't have yet): PR-AUC /
Recall@low-FPR / False-Trust (require per-item confidence outputs) and
judge-graded scores (require the judge-model hook).
"""
import json
import math
import re


def jaccard(a, b) -> float:
    """Set overlap in [0,1] — the PurpleLlama multi-select methodology."""
    sa, sb = set(a), set(b)
    inter = len(sa & sb)
    union = len(sa) + len(sb) - inter
    return inter / union if union > 0 else 0.0


def normalize_letters(vals) -> list:
    """['a)', ' B'] -> ['A', 'B'] — first alphabetic char, uppercased."""
    out = []
    if isinstance(vals, str):
        vals = [vals]
    for v in vals or []:
        m = re.search(r"[A-Za-z]", str(v))
        if m:
            out.append(m.group(0).upper())
    return out


# ---------------------------------------------------------------------------
# Per-item scorers
# ---------------------------------------------------------------------------
def exact_match(pred, gold) -> float:
    """1.0 iff pred == gold after str/strip/upper normalization (None -> 0)."""
    if pred is None:
        return 0.0
    return 1.0 if str(pred).strip().upper() == str(gold).strip().upper() else 0.0


def abs_error(pred, gold, worst: float) -> float:
    """|pred - gold| for regression tasks (CVSS etc.). None/unparseable -> worst
    (never 0 — a refusal must not look like a perfect prediction)."""
    try:
        return abs(float(pred) - float(gold))
    except (TypeError, ValueError):
        return worst


def set_prf(pred, gold) -> dict:
    """Precision/recall/F1 + tp/fp/fn counts for one item's extracted set
    (entities, techniques, PII spans...). Feeds mean-F1 or micro_f1."""
    ps, gs = set(pred or []), set(gold or [])
    tp, fp, fn = len(ps & gs), len(ps - gs), len(gs - ps)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": p, "recall": r, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def ndcg_at_k(ranked, gains: dict, k: int) -> float:
    """NDCG@k for one ranking (prioritization tasks). `ranked` = ids in model
    order; `gains` = id -> relevance. None/empty ranking -> 0."""
    ideal = sorted(gains.values(), reverse=True)[:k]
    idcg = sum(g / math.log2(i + 2) for i, g in enumerate(ideal))
    if not idcg:
        return 0.0
    dcg = sum(gains.get(x, 0.0) / math.log2(i + 2)
              for i, x in enumerate((ranked or [])[:k]))
    return dcg / idcg


def pass_at_k(n: int, c: int, k: int) -> float:
    """Unbiased pass@k from n samples with c successes (agentic import path)."""
    if n - c < k:
        return 1.0
    return 1.0 - math.prod((n - c - i) / (n - i) for i in range(k))


def hier_match(pred, gold, parents: dict, partial_credit: float = 0.75) -> float:
    """Exact match with hierarchy credit (e.g. CWE tree): 1.0 exact, `partial_credit`
    if pred and gold share a parent/child edge, else 0. `parents` = id -> parent id."""
    if pred is None:
        return 0.0
    p, g = str(pred).strip().upper(), str(gold).strip().upper()
    if p == g:
        return 1.0
    if parents.get(p) == g or parents.get(g) == p or \
            (parents.get(p) is not None and parents.get(p) == parents.get(g)):
        return partial_credit
    return 0.0


# ---------------------------------------------------------------------------
# Aggregators: list of per-item score dicts -> one domain score
# ---------------------------------------------------------------------------
def _mean(items, mid):
    return sum(d[mid] for d in items) / len(items) if items else 0.0


def _macro_f1(items, mid):
    """Corpus macro-F1 over per-item {"pair": (pred, gold)} label pairs.
    Unanswered items carry pred=None and count as a miss for their gold class."""
    pairs = [d["pair"] for d in items]
    classes = sorted({str(g) for _, g in pairs} | {str(p) for p, _ in pairs if p is not None})
    f1s = []
    for c in classes:
        tp = sum(1 for p, g in pairs if str(p) == c and str(g) == c)
        fp = sum(1 for p, g in pairs if str(p) == c and str(g) != c)
        fn = sum(1 for p, g in pairs if str(p) != c and str(g) == c)
        f1s.append(2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0)
    return sum(f1s) / len(f1s) if f1s else 0.0


def _micro_f1(items, mid):
    """Corpus micro-F1 over per-item tp/fp/fn counts (extraction tasks)."""
    tp = sum(d["tp"] for d in items)
    fp = sum(d["fp"] for d in items)
    fn = sum(d["fn"] for d in items)
    return 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0


def _mcc(items, mid):
    """Matthews corr. coeff. over binary {"pair": (pred, gold)} items (0/1 labels;
    pred=None counts as the wrong class). PrimeVul-style detection."""
    def as01(v):
        return 1 if str(v).strip() in ("1", "1.0", "True", "true") else 0
    tp = fp = tn = fn = 0
    for d in items:
        p, g = d["pair"]
        p, g = (0 if p is None else as01(p)), as01(g)
        if p and g:
            tp += 1
        elif p and not g:
            fp += 1
        elif not p and g:
            fn += 1
        else:
            tn += 1
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return ((tp * tn) - (fp * fn)) / denom if denom else 0.0


AGGREGATORS = {
    "mean": _mean,          # default — accuracy, jaccard, MAE, NDCG, ASR/FRR, pass@k, item-F1
    "macro_f1": _macro_f1,  # multi-class classification (per-class balance)
    "micro_f1": _micro_f1,  # extraction (pooled tp/fp/fn)
    "mcc": _mcc,            # binary detection under imbalance
}


def extract_json(text: str):
    """Last brace-balanced JSON object, preferring one with 'correct_answers'.

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
