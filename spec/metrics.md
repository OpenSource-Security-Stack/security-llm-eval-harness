# Metrics — which one fits which task (and why)

Every task is scored on a **primary quality metric** chosen to match (a) the model's output shape
and (b) the task's error asymmetry (which mistake is costly). The router ranks models *within* a
task on this metric, then composes it with universal secondary axes: **cost, latency, reliability
(answered rate), and calibration.** Full detail in `docs/METRICS_MAP.md`.

| metric id | family | used for | provenance |
|---|---|---|---|
| `jaccard` | set overlap | multi-select MCQ (CTI, malware) | PurpleLlama / CyberSOCEval |
| `accuracy` | classification | knowledge MCQ, attribution | standard |
| `hierarchical_f1` | multi-label | ATT&CK / Sigma technique mapping | cotool Sigma (0.75 parent credit) |
| `exact_match_hier` | classification | CVE to CWE | CTIBench-RCM (+ hierarchical credit) |
| `mae` | regression | CVSS severity scoring | CTIBench-VSP |
| `vd_score_prauc` | detection | code vuln detection | PrimeVul (FNR @ <=0.5% FPR) + PR-AUC |
| `pass@k_subtask` | agentic | CTF / exploitation | Cybench subtask credit |
| `asr` / `frr` | safety | refusal / over-refusal | Meta CyberSecEval (paired on Pareto frontier) |
| `f1_baseline_fpr` | detection | insider threat | OrgForge-IT |

## Recommended upgrades (from the metrics survey)
- **PR-AUC over ROC-AUC** for any imbalanced detection task (ROC stays optimistic under imbalance).
- **Recall @ fixed low-FPR** as the deployable operating point, not threshold-averaged F1/AUC.
- **False Trust rate** (confident-but-insecure) as the headline safety-calibration metric; build
  confidence on verbalized + sampling-consistency, **not** logprobs.
- **AUGRC** for abstention / routing hand-off decisions.
- **Temporal / post-cutoff splits** as the primary contamination defense (drift alone is
  diagnostic-only — LLM paraphrase erases it).
