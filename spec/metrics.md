# Metrics — which one fits which task (and why)

Every task is scored on a **primary quality metric** chosen to match (a) the model's output shape
and (b) the task's error asymmetry (which mistake is costly). The router ranks models *within* a
task on this metric, then composes it with universal secondary axes: **cost, latency, reliability
(answered rate), and calibration.** Full detail in `docs/METRICS_MAP.md`.

| metric id | family | used for | provenance | harness support |
|---|---|---|---|---|
| `jaccard` | set overlap | multi-select MCQ (CTI, malware) | PurpleLlama / CyberSOCEval | ✅ live (`jaccard`) |
| `accuracy` | classification | knowledge MCQ, attribution, CVE→CWE | standard | ✅ live (`exact_match`) |
| `macro_f1` / `micro_f1` | classification / extraction | CWE-type, ATT&CK-technique extraction, PII | standard | ✅ ready (corpus aggregators) |
| `mcc` | detection | code vuln detection (binary, imbalanced) | PrimeVul | ✅ ready (aggregator) |
| `mae` | regression | CVSS severity scoring | CTIBench-VSP | ✅ ready (`abs_error`, direction: lower, None→worst) |
| `ndcg@k` | ranking | vuln prioritization (KEV/EPSS) | standard IR | ✅ ready (`ndcg_at_k`) |
| `pass@k` | agentic | CTF / exploitation (import path) | Cybench et al. | ✅ ready (`pass_at_k`) |
| `asr` / `frr` | safety | refusal / over-refusal | Meta CyberSecEval | ✅ ready (mean of flags, direction: lower) |
| `hier credit` | classification | CVE→CWE with CWE-tree partial credit | cotool Sigma (0.75 parent) | ✅ ready (`hier_match`, benchmark supplies parent map) |
| `vd_score_prauc` / Recall@low-FPR | detection | code vuln detection ops point | PrimeVul | ⏳ needs per-item confidence outputs |
| judge-graded (StrongREJECT etc.) | safety / codegen | graded harmfulness, secure-code quality | StrongREJECT | ⏳ needs judge-model hook |

**How a benchmark uses these:** its `Task.score(pred, gold)` composes the per-item primitives
(returning that metric's WORST for `pred=None` — refusals must never score well), and
`Task.metric = {"id", "direction", "aggregate"}` picks the aggregator (`mean` default;
`macro_f1` / `micro_f1` / `mcc` are corpus-level). The bootstrap CI resamples items and
re-aggregates, so it is correct for corpus-level metrics too. Tests: `tests/test_metrics.py`.

## Recommended upgrades (from the metrics survey)
- **PR-AUC over ROC-AUC** for any imbalanced detection task (ROC stays optimistic under imbalance).
- **Recall @ fixed low-FPR** as the deployable operating point, not threshold-averaged F1/AUC.
- **False Trust rate** (confident-but-insecure) as the headline safety-calibration metric; build
  confidence on verbalized + sampling-consistency, **not** logprobs.
- **AUGRC** for abstention / routing hand-off decisions.
- **Temporal / post-cutoff splits** as the primary contamination defense (drift alone is
  diagnostic-only — LLM paraphrase erases it).
