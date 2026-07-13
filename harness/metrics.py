"""Pure metric + parsing helpers. No I/O, no state — safe for any benchmark."""
import json
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
