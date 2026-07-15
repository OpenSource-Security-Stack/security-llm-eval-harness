# security-llm-eval-harness

Open evaluation harness for measuring **how well LLMs perform security tasks** — one metric
per task, cost/latency/reliability tracked alongside quality. It produces a `rankings.json`
rendered by the [security-llm-leaderboard](../security-llm-leaderboard).

**harness → rankings.json → leaderboard.**

## Why

No single model is best across security tasks. On CyberSOCEval the ranking reshuffles between
malware analysis and threat-intel; open-weight models win on some leaves and lose on others.
This harness measures those per-task differences reproducibly, so the right model can be
chosen for each task.

## How it works

**Plugins ask, engine runs, contract publishes.** Each benchmark is a small plugin answering
four questions — where's my data, how do I ask, how do I read the answer, how do I grade it —
plus its metric metadata. The engine handles everything else identically for every benchmark:
model fan-out, retries, cost tracking, append-only results. Export squashes results into
`rankings.json`.

```
harness/              # THE ENGINE — benchmark-agnostic
  config.py             # paths, .env loading, $SECEVAL_DATA_DIR dataset override
  models.py             # model roster, provider clients, pricing
  metrics.py            # pure metric fns (jaccard, letter parsing, …)
  task.py               # the Task plugin interface (4 fns + metric metadata)
  runner.py             # generic run loop → results/*.jsonl
  scoring.py            # records → model stats + mixture stats
  export.py             # results → rankings.json (the contract)
benchmarks/           # THE PLUGINS — one folder per benchmark
  cybersoceval/         # malware + CTI tasks (Jaccard, PurpleLlama methodology)
plugins/              # open-core seam — private benchmarks live here (gitignored)
spec/                 # THE CONTRACT — shared with the leaderboard
  taxonomy.json         # 19 domains × tasks × target benchmark × metric × status
  results.schema.json   # JSON Schema for rankings.json
  metrics.md            # which metric fits which task (+ provenance)
scripts/
  run.py                # run a task against the roster (spends API $)
  export.py             # results/*.jsonl → rankings.json (no spend)
results/              # raw per-question outputs (*.jsonl, append-only)
docs/                 # the domain / eval / metric maps
```

## Quickstart

```bash
# keys (never committed): create .env with OPENAI_API_KEY / TOGETHER_API_KEY / ANTHROPIC_API_KEY
# datasets: a PurpleLlama checkout next to this repo (or set $SECEVAL_DATA_DIR)
python3 scripts/run.py --list                  # show registered tasks
python3 scripts/run.py --task cti --n 30       # run one task (spends API $)
python3 scripts/export.py                      # → rankings.json + rankings.js (no spend)
```

## Adding a benchmark

Create `benchmarks/<name>/bench.py`, build a `harness.task.Task` with your `load / prompt /
parse / score` functions and metric metadata, and register it in `benchmarks/__init__.py`.
Results produced outside this engine (e.g. sandboxed agentic evals) can join at the export
layer instead via `Task.load_results` — the contract doesn't care how a score was produced.

## Open-core

The framework and the open-benchmark adapters are MIT-licensed. Proprietary benchmarks, custom
scoring, or routing heuristics can be kept private via the `plugins/` seam (see
`plugins/README.md`) without forking — they register against the public interfaces and are never
committed to this repo. The **only** thing consumers depend on is the stable `rankings.json`
contract in `spec/`.

## Status

Live leaves: `malware.sandbox_interpretation`, `cti.ti_reasoning` (CyberSOCEval). Everything else
in `spec/taxonomy.json` is mapped and queued. See `docs/UNIFIED_MAP.md`.

## License

MIT — see [LICENSE](LICENSE).
