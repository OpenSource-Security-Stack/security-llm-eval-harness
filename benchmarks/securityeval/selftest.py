"""No-API self-test for the SecurityEval plugin.

Exercises the REAL Bandit scoring path (no model calls):
  - load() returns the 121 items; prints the count and one full prompt().
  - score() on a hand-written INSECURE snippet must be 0.0.
  - score() on a benign SAFE snippet must be 1.0.
  - score(None, gold) must be 0.0.
  - parse() extracts a ```python code block.

Run:  benchmarks/securityeval/.venv/bin/python benchmarks/securityeval/selftest.py
(or any python that can import the harness; it shells out to the venv bandit).
"""
import sys
from pathlib import Path

# Make the repo importable when run directly.
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from benchmarks.securityeval import bench  # noqa: E402

fails = []


def check(name, cond):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        fails.append(name)


# --- load ------------------------------------------------------------------
items = bench.load()
check(f"load() returned 121 items (got {len(items)})", len(items) == 121)

# --- one full prompt -------------------------------------------------------
print("\n===== EXAMPLE PROMPT (item 0) =====")
print(bench.prompt(items[0]))
print("===== END PROMPT =====\n")

# --- parse -----------------------------------------------------------------
raw = "Here you go:\n```python\nimport os\n\ndef f():\n    return os.getcwd()\n```\nDone."
parsed = bench.parse(raw)
check("parse() extracts code block", parsed is not None and "os.getcwd" in parsed)
check("parse('') is None", bench.parse("") is None)

# --- score: INSECURE snippet (command injection via shell=True) -----------
insecure = (
    "import subprocess\n"
    "\n"
    "def run(cmd):\n"
    "    subprocess.call(cmd, shell=True)\n"
)
s_insecure = bench.score(insecure, "CWE-078")
check(f"insecure snippet scores 0.0 (got {s_insecure})",
      s_insecure["secure_at_1"] == 0.0)

# --- score: another INSECURE snippet (weak hash md5) ----------------------
insecure2 = (
    "import hashlib\n"
    "\n"
    "def digest(x):\n"
    "    return hashlib.md5(x).hexdigest()\n"
)
s_insecure2 = bench.score(insecure2, "CWE-327")
check(f"md5 snippet scores 0.0 (got {s_insecure2})",
      s_insecure2["secure_at_1"] == 0.0)

# --- score: SAFE snippet ---------------------------------------------------
safe = (
    "def add(a, b):\n"
    "    return a + b\n"
)
s_safe = bench.score(safe, "CWE-020")
check(f"safe snippet scores 1.0 (got {s_safe})", s_safe["secure_at_1"] == 1.0)

# --- score: None -----------------------------------------------------------
s_none = bench.score(None, "CWE-020")
check(f"score(None) is 0.0 (got {s_none})", s_none["secure_at_1"] == 0.0)

# --- score: unparseable code ----------------------------------------------
s_bad = bench.score("def broken(:\n    pass\n", "CWE-020")
check(f"syntax-error code scores 0.0 (got {s_bad})", s_bad["secure_at_1"] == 0.0)

print()
if fails:
    print(f"OVERALL: FAIL ({len(fails)} failed: {fails})")
    sys.exit(1)
print("OVERALL: PASS")
