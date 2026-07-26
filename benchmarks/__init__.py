"""Benchmark registry.

Public benchmarks are registered on import below. Private benchmarks
(open-core seam) live in plugins/private/ — if a `plugins.private` package
exists and exposes `register_all(register)`, its tasks join the same registry.
"""
REGISTRY = {}


def register(task):
    if task.id in REGISTRY:
        raise ValueError(f"duplicate task id '{task.id}'")
    REGISTRY[task.id] = task


def get(task_id):
    if task_id not in REGISTRY:
        raise KeyError(f"unknown task '{task_id}'. known: {sorted(REGISTRY)}")
    return REGISTRY[task_id]


def all_tasks():
    return [REGISTRY[k] for k in sorted(REGISTRY)]


# --- public benchmarks -------------------------------------------------------
from .cybersoceval import CTI, MALWARE  # noqa: E402
from .ctibench import ATE, CVE_CWE, CVSS, MCQ  # noqa: E402
from .sigma import SIGMA_ATTACK  # noqa: E402
from .vuln_prioritization import VULN_PRIO  # noqa: E402
from .primevul import PRIMEVUL  # noqa: E402
from .securityeval import SECURITYEVAL  # noqa: E402
# Evaluated but NOT admitted (both discriminated poorly): vuldetect_cwe saturated
# because Juliet/SARD identifiers leak the CWE; iac_eval's non-regression Checkov
# scoring rewarded under-production (inverted ranking). Kept out of the registry.

register(CTI)
register(MALWARE)
register(CVE_CWE)
register(CVSS)
register(MCQ)
register(ATE)
register(SIGMA_ATTACK)
register(VULN_PRIO)
register(PRIMEVUL)
register(SECURITYEVAL)

# --- private benchmarks (gitignored; absent in the public checkout) ----------
try:
    from plugins.private import register_all as _private_register_all  # type: ignore
    _private_register_all(register)
except ImportError:
    pass
