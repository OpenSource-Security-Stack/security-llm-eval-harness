# Security LLM Evals — Metrics Map (which metric fits which domain)

For each routable domain: the **output shape** the model produces, the **primary metric** that
fits, the **error asymmetry** (which mistake is costly → what the metric must weight), and the
**benchmark** that measures it. Models are ranked *within* a domain on the primary metric,
then composes it with the universal secondary axes (cost / latency / reliability).

Two rules drive every choice:
1. **Metric must match output shape** — a set → set-overlap metric; a label → classification; a
   number → regression; a generation → exec/judge; an agent run → success/pass@k.
2. **Metric must match error asymmetry** — where **false positives** are costly (SOC alerts,
   SAST) weight **precision / constrain FPR**; where **false negatives** are costly (malware, IR,
   real-vuln detection) weight **recall**.

---

## Primary quality metric per domain

| Domain / task | Output shape | Primary metric | Error asymmetry → what it weights | Benchmark |
|---|---|---|---|---|
| **SOC — alert triage** | label (TP/FP, severity) | **Precision / Recall / F1**, FP-rate | FP costly (alert fatigue) → precision | BOTSv3 |
| **SOC — investigation Q&A** | short answer | **Exact-match accuracy** | balanced | BOTSv3, ExCyTIn |
| **SOC — IoC extraction** | entity set | **Entity-level F1** | recall (miss = blind spot) | SEvenLLM |
| **CTI — knowledge / attribution** | single choice/label | **Accuracy** | balanced | CTIBench-MCQ |
| **CTI — multi-select reasoning** | letter set | **Jaccard (meanJac)** | balanced | CyberSOCEval-CTI ✅ |
| **CTI — ATT&CK technique extraction** | technique-ID set | **Hierarchical multi-label F1** | hierarchy → partial credit for parent | CTIBench-ATE, AthenaBench |
| **Malware — report interpretation** | letter set | **Jaccard (meanJac)** | balanced | CyberSOCEval-malware ✅ |
| **Malware — behavior classification** | labels | **Macro-F1** | FN costly (missed capability) → recall | behavior-audit sets |
| **Vuln Mgmt — CVE→CWE (RCM)** | 1 CWE of ~900 | **Exact-match accuracy** (+ hierarchical/top-k partial credit) | close-cousin CWEs → hierarchical credit | CTIBench-RCM ⭐ |
| **Vuln Mgmt — CVSS scoring (VSP)** | numeric score/vector | **MAE / MAD** (regression); per-component accuracy | under-scoring severity costly | CTIBench-VSP |
| **Vuln Mgmt — prioritization** | ranking | **NDCG, Precision@k** | must surface exploitable first | KEV/EPSS-based (custom) |
| **Code Sec — vuln detection (binary)** | yes/no | **VD-Score (FNR @ ≤0.5% FPR)**, F1, MCC, pairwise-acc | FP destroys SAST trust → constrain FPR; FN = missed bug | PrimeVul, VulDetectBench |
| **Code Sec — CWE-type ID** | class | **Accuracy / F1** | balanced | VulDetectBench T2 |
| **Code Sec — secure code gen** | code | **Vulnerable-rate (secure@k)** + functional-pass | insecure output *and* over-refusal both costly | SecurityEval, CyberSecEval |
| **Code Sec — vuln repair** | code | **Functional-test + security-check pass** (or exact-match) | must fix without breaking function | VulRepair |
| **Detection Eng — Sigma→ATT&CK** | technique-ID set | **Hierarchical multi-label F1** | partial credit for parent technique | Sigma→ATT&CK (SigmaHQ-derived) ⭐ |
| **Detection Eng — rule generation** | rule (YAML) | **Syntactic validity + detection efficacy** (TP on attack / FP on benign) | FP costly | GenTI, CTI-REALM |
| **DFIR — knowledge** | MCQ | **Accuracy** | balanced | DFIR-Metric I |
| **Offense — CTF / exploitation** | flag / success | **Success-rate, pass@k**; capability-milestone score | binary; partial via milestones | Cybench, 3CB, NYU CTF |
| **Safety — malicious refusal** | refuse/comply | **Attack-Success-Rate (ASR ↓)** | complying with harm costly | CyberSecEval-MITRE, HarmBench |
| **Safety — over-refusal** | refuse/comply (benign) | **False-Refusal-Rate (FRR ↓)** | over-refusal kills utility | CyberSecEval-FRR |
| **Agent Sec — prompt injection** | action | **ASR under attack (↓) + task-utility retained** | two-sided | AgentDojo, InjecAgent |

---

## Universal secondary axes (folded in for *every* domain)
- **Reliability** — parse/format-adherence / answered rate (a right answer you can't parse = wrong).
- **Cost** — $/task and **$/correct** (quality-weighted cost).
- **Latency** — time/task. Weighted heavily for real-time SOC, lightly for async vuln-mgmt.
- **Calibration** — does the model know when it's unsure (drives human-handoff + routing confidence).

## Metric families (the toolbox)
- **Classification** — accuracy, precision, recall, F1, FPR/FNR, MCC, AUC
- **Set / multi-label** — Jaccard, hierarchical F1, exact-set-match
- **Ranking** — NDCG, Precision@k, MAP
- **Regression** — MAE / MAD, RMSE
- **Generation** — exact-match, pass@k, functional+security checks, LLM-judge, ROUGE/BLEU
- **Agentic** — success-rate, pass@k, capability-milestone, efficiency (cost/turns)
- **Safety** — ASR, FRR, refusal-rate

## Ranking design notes
- Metrics rank models **within** a domain — cross-domain comparability isn't required. Normalize
  each to 0–1 only for dashboards.
- The routing objective = **quality metric × cost × latency × reliability**, weighted by the
  domain's needs (real-time SOC weights latency; async triage weights quality/cost). `$/correct`
  is the simplest quality-weighted-cost composite and what we already report.
- Prefer metrics/benchmarks that still **separate models** (avoid saturated MCQ sets; watch for
  contamination — favor leakage-resistant sets like AthenaBench where possible).
