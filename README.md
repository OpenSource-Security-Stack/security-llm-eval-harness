# security-llm-eval-harness

Open evaluation harness for measuring **how well LLMs perform security tasks** — one metric
per task, cost/latency/reliability tracked alongside quality. It produces a `rankings.json`
that the [security-llm-leaderboard](../security-llm-leaderboard) renders and that a router can
consume to pick the best model per task.

Part of the Security Router project: **harness → rankings → leaderboard / router.**

## Why

No single model is best across security tasks. On CyberSOCEval the ranking reshuffles between
malware analysis and threat-intel; open-weight models win on some leaves and lose on others.
This harness measures those per-task differences reproducibly so routing can act on them.

## What's here

```
run_cybersoceval.py   # task-aware runner (malware + CTI leaves), multi-provider, cost-aware
mixture_analysis.py   # offline "mixture of models" analysis over cached results
full_analysis.py      # cross-leaf comparison → ANALYSIS.md
spec/                 # THE CONTRACT — shared with the leaderboard + router
  taxonomy.json         # 19 domains × tasks × target benchmark × metric × status
  results.schema.json   # JSON Schema for rankings.json
  metrics.md            # which metric fits which task (+ provenance)
scripts/
  export_rankings.py    # results/*.jsonl → rankings.json (the leaderboard's input)
plugins/              # open-core seam — private benchmarks/metrics live here (gitignored)
benchmarks/           # open benchmark adapters (add new ones here)
results/              # raw per-question outputs (*.jsonl)
docs/                 # the domain / eval / metric maps
```

## Quickstart

```bash
# keys (never committed): create .env with OPENAI_API_KEY / TOGETHER_API_KEY / ANTHROPIC_API_KEY
python3 run_cybersoceval.py --task cti --n 30
python3 scripts/export_rankings.py         # → rankings.json
```

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
