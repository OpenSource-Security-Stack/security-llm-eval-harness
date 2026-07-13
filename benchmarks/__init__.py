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

register(CTI)
register(MALWARE)

# --- private benchmarks (gitignored; absent in the public checkout) ----------
try:
    from plugins.private import register_all as _private_register_all  # type: ignore
    _private_register_all(register)
except ImportError:
    pass
