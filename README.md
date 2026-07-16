# security-llm-eval-harness

Open evaluation harness for measuring **how well LLMs perform security tasks** — accuracy,
cost, and reliability, per task. It runs models against publicly available security benchmarks
and produces the `rankings.json` rendered by
[security-llm-leaderboard](https://github.com/OpenSource-Security-Stack/security-llm-leaderboard)
— live at [secllmleaderboard.dev](https://secllmleaderboard.dev).

Currently: **4 domains, 7 benchmarks, 6 models** — threat intelligence, malware analysis,
detection engineering, and vulnerability management.

## Setup

```bash
git clone https://github.com/OpenSource-Security-Stack/security-llm-eval-harness.git
cd security-llm-eval-harness

# 1. API keys (never committed): create a .env in the repo root
#    OPENAI_API_KEY=...  TOGETHER_API_KEY=...  ANTHROPIC_API_KEY=...

# 2. Datasets: each benchmark documents its fetch command in benchmarks/<name>/bench.py
#    (e.g. CTIBench TSVs from HuggingFace, SigmaHQ rules from GitHub). CyberSOCEval needs
#    a PurpleLlama checkout next to this repo, or set $SECEVAL_DATA_DIR.

# 3. Run
python3 scripts/run.py --list                  # show registered benchmarks
python3 scripts/run.py --task cti_mcq --n 50   # run one benchmark (spends API $)
python3 scripts/export.py                      # results → rankings.json (no spend)
```

Raw per-question results land in `results/*.jsonl` (append-only; runs are resumable — rerunning
skips already-answered questions). `scripts/export.py` rebuilds `rankings.json` from everything
cached, at no API cost.

## Contributing

**Add a benchmark:** create `benchmarks/<name>/bench.py`, build a `harness.task.Task` with your
`load / prompt / parse / score` functions and metric metadata, register it in
`benchmarks/__init__.py`. Only publicly available, licensed datasets are accepted — see
`spec/benchmark-policy.md`; every benchmark is credited to its original authors.

**Add a model:** add a roster entry in `harness/models.py` (provider + API id + pricing).

**Add a metric:** pure functions in `harness/metrics.py`, with tests in `tests/`.

Run the tests before a PR: `python3 tests/test_metrics.py && python3 tests/test_rollup.py`

Issues and PRs welcome — a benchmark or model you think belongs here is exactly the
contribution we want.

## License

MIT — see [LICENSE](LICENSE). Benchmark data belongs to its original authors (each dataset's
license is recorded in `spec/taxonomy.json` and shown on the leaderboard's credits page).
