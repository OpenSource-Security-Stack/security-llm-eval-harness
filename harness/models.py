"""Model roster, provider clients, pricing.

OSS models run on Together; GPT models on OpenAI (both OpenAI-compatible
/v1/chat/completions); Claude on the Anthropic Messages API. Keys come from
os.environ (see config.load_env) and are never printed.
"""
import json
import os
import time
import urllib.error
import urllib.request

USER_AGENT = "security-router-eval/0.1"

# friendly key -> (provider, api_id)
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
# Together ids listed here act as FALLBACKS when the live lookup returns no/zero
# price (e.g. a delisted endpoint) — pinned to the price in effect at run time.
PRICES_MANUAL = {
    "gpt-5.1":         {"input": 1.25, "output": 10.0},   # confirmed by user
    "gpt-5.5":         {"input": 1.25, "output": 10.0},   # PLACEHOLDER (= gpt-5.1); confirm
    "claude-opus-4-8": {"input": 15.0, "output": 75.0},   # PLACEHOLDER (std Opus tier); confirm
    "Qwen/Qwen3-235B-A22B-Instruct-2507-tput": {"input": 0.20, "output": 0.60},  # delisted 2026-07
}
PRICES = {}  # filled by load_prices(): model_key -> {"input":$/1M, "output":$/1M}


def load_prices() -> None:
    """Populate PRICES for every roster model: live Together + manual constants."""
    _, keyname = PROVIDERS["together"]
    req = urllib.request.Request(
        "https://api.together.xyz/v1/models",
        headers={"Authorization": f"Bearer {os.environ.get(keyname, '')}",
                 "User-Agent": USER_AGENT},
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
            live = together.get(mid, {"input": 0, "output": 0})
            if not (live["input"] or live["output"]):          # missing/delisted -> fallback
                live = PRICES_MANUAL.get(mid, live)
            PRICES[key] = live
        else:
            PRICES[key] = PRICES_MANUAL.get(mid, {"input": 0, "output": 0})


def cost_usd(model_key: str, prompt_tok, completion_tok) -> float:
    p = PRICES.get(model_key, {"input": 0, "output": 0})
    return ((prompt_tok or 0) / 1e6 * p["input"]
            + (completion_tok or 0) / 1e6 * p["output"])


def call_model(provider: str, model_id: str, prompt: str, timeout: int = 180):
    """One prompt -> {content, latency, prompt_tokens, completion_tokens} or {error, latency}.

    Retries 429/5xx with linear backoff (4 attempts)."""
    url, keyname = PROVIDERS[provider]
    key = os.environ.get(keyname, "")
    if provider == "anthropic":
        # Anthropic Messages API: different endpoint/headers/body/response shape.
        # NB: temperature is deprecated/rejected for opus-4.8 — omit it.
        body = {"model": model_id, "max_tokens": 8192,
                "messages": [{"role": "user", "content": prompt}]}
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01",
                   "content-type": "application/json", "User-Agent": USER_AGENT}
    else:  # openai-compatible (openai, together)
        body = {"model": model_id, "messages": [{"role": "user", "content": prompt}]}
        if provider == "together":
            body["temperature"] = 0
            body["max_tokens"] = 24576
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                   "User-Agent": USER_AGENT}
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
