"""The benchmark plugin interface.

A Task is one leaderboard domain: a dataset, a way to ask, a way to read the
answer, and a way to grade it. The engine (runner/export) handles everything
else — model fan-out, retries, cost, jsonl persistence, rankings.json.

Two ways a Task feeds rankings.json:
  - run it (runner.run) -> fresh results/*.jsonl        (needs load/prompt/parse/score)
  - import it (load_results) -> pre-existing per-item records, e.g. cached runs
    or scores produced outside this engine (sandbox/agentic evals).
"""
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Task:
    # identity — `id` is the domain key in rankings.json (e.g. "cti")
    id: str
    name: str                      # display name, e.g. "Threat-Intel Reasoning"
    suite: str                     # e.g. "CyberSOCEval (Meta × CrowdStrike)"
    benchmark_line: str            # provenance line shown on the leaderboard

    # metric metadata — export uses this instead of assuming mean/higher-better
    metric: dict = field(default_factory=lambda: {
        "id": "jaccard", "direction": "higher", "aggregate": "mean"})

    # the 4 questions (+ item identity helpers)
    load: Optional[Callable] = None      # () -> list[item]
    key: Optional[Callable] = None       # item -> stable question id
    strata: Optional[Callable] = None    # item -> stratum for balanced subsets
    gold: Optional[Callable] = None      # item -> ground truth
    prompt: Optional[Callable] = None    # item -> prompt string
    parse: Optional[Callable] = None     # response text -> prediction | None
    score: Optional[Callable] = None     # (prediction, gold) -> dict of per-item metrics

    # optional import path: () -> list[record] with _qid/model/model_answers/...
    load_results: Optional[Callable] = None

    def runnable(self) -> bool:
        return all([self.load, self.key, self.strata, self.gold, self.prompt,
                    self.parse, self.score])
