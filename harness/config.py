"""Central config: repo paths, dataset root, .env loading.

Dataset location resolves in this order:
  1. $SECROUTER_DATA_DIR (explicit override — set this if your layout differs)
  2. <repo>/../PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta
     (the default sibling-checkout layout: inferenceplatform/{this repo, PurpleLlama})

Secrets are never stored here. `load_env()` reads KEY=VALUE lines into
os.environ from the first .env it finds:
  1. <repo>/.env
  2. <repo>/../security-router/.env   (local-dev convenience; never committed)
"""
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RESULTS = REPO / "results"
CACHE = REPO / "cache"

_ENV_CANDIDATES = [REPO / ".env", REPO.parent / "security-router" / ".env"]


def data_dir() -> Path:
    """PurpleLlama crwd_meta dataset root (lazy — honors .env-loaded overrides)."""
    override = os.environ.get("SECROUTER_DATA_DIR")
    if override:
        return Path(override).expanduser()
    return REPO.parent / "PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta"


def load_env() -> Path | None:
    """Load the first .env found (existing os.environ values win). Returns its path."""
    for path in _ENV_CANDIDATES:
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())
        return path
    return None
