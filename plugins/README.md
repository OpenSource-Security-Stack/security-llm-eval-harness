# plugins/ — the open-core seam

This is where **private / proprietary** benchmarks, metrics, and scoring live. Nothing under
`plugins/private/` is committed to the public repo (it's in `.gitignore`), so you can keep custom
logic closed while the framework stays open.

## How it works

The public harness exposes stable interfaces (a benchmark runner, a metric registry, a provider
layer). A plugin implements one of those interfaces and registers itself — it does **not** fork
the core. Two ways to keep it private:

1. **Local, gitignored** — drop it in `plugins/private/`. Runs locally, never published.
2. **Separate private repo** — a `security-llm-eval-harness-private` package that `pip install`s
   this public core and registers extra benchmarks/metrics. Cleanest for a team.

## What's safe to keep private here
- Proprietary benchmark datasets or task adapters
- Custom scoring / weighting logic (e.g. a domain-specific composite)
- Router-specific ranking heuristics

## What must stay public (the contract)
- `spec/results.schema.json` — the `rankings.json` shape
- `spec/taxonomy.json` — domain/task ids

As long as a private plugin emits `rankings.json` that matches the schema, the public leaderboard
and any consumer keep working — they never see your private logic.

```
plugins/
  README.md          # this file (public)
  private/           # gitignored — your closed logic
    my_metric.py
    my_benchmark.py
```
