# Security Router — Eval Map (by domain)

Benchmarks for evaluating LLMs/agents on security tasks, grouped by taxonomy domain.
Built from the 2026-07 landscape survey (+ cotool.ai). See `reference-security-eval-landscape`
(memory) for full source links. Refreshed 2026-07-12 via deep search (new finds marked 🆕;
"repo unverified" = paper exists but no public artifact confirmed — check before adopting).
Meta-resource for future refreshes: `EvanThomasLuke/Awesome-AI-Security-Benchmarks` (~175
benchmarks, maintained through ≥2026-02).

**Runnability**
- 🟢 **API** — plain API calls, automated scoring (MCQ / exact-match / F1). Runs on our harness today.
- 🟡 **API+judge/analyzer** — API calls but scoring needs a judge model or a static analyzer (CodeQL/Bandit/weggli).
- 🔴 **Sandbox** — needs Docker / live environment / execution. Heavier, later phase.

**Status**
- ✅ done  ·  ⭐ recommended next  ·  ◻︎ candidate

---

## 1. SOC / Incident Response / Alert Triage
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| CyberSOCEval (malware + CTI) | 🟢 | ✅ | Interpret detonation/threat reports → multi-select answers (Meta × CrowdStrike). *Already run.* |
| SEvenLLM | 🟡 | ◻︎ | Read incident report → extract IoCs, prioritize alerts, summarize. 1,300 Q, judge-scored. |
| BOTSv3 (cotool) | 🔴 | ◻︎ | Agent queries a live **Splunk** SIEM (2.7M logs) to answer IR/hunting questions. |
| macOS / Windows Enterprise Intrusion (cotool) | 🔴 | ◻︎ | Agentic multi-host investigation: IR + detection + forensics across AD/endpoints. |
| ExCyTIn-Bench (Microsoft) | 🔴 | ◻︎ | Agent investigates a simulated Azure/Sentinel SOC; 7,542 Q over attack graphs. |
| 🆕 SIABench (Concordia+DRDC, 2026) | 🔴 | ◻︎ | 25 deep-investigation scenarios (229 Q) + 135 triage scenarios; agent runs forensic tools (Tshark/Volatility) in a Kali VM. Ranks 11 models (Claude 4.5 Sonnet & GPT-5 top; best solves 8/25). Only an excerpt public. |
| 🆕 Cyber Defense Benchmark (2026-04) | 🔴 | ◻︎ | Agentic threat hunting: SQL over 75–135k Windows event logs (Gymnasium env), flag malicious timestamps. Best frontier model ≈3.8%. Repo unverified. |
| 🆕 DefenderBench | 🔴 | ◻︎ | Defensive/SOC-style agent tasks in text-based environments. Public GitHub. |

## 2. Threat Intelligence (CTI)
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| CyberSOCEval — CTI task | 🟢 | ✅ | Reason over CrowdStrike threat reports → multi-select. *Already run.* |
| CTIBench | 🟢 | ◻︎ | 5 tasks: knowledge MCQ (2,500) + RCM + VSP + ATT&CK extraction + actor attribution. The CTI standard. |
| CTIArena | 🟡 | ◻︎ | Multi-source CTI reasoning: campaign storyline, actor profiling, malware lineage. 691 Q. |
| AthenaBench | 🟢 | ◻︎ | Leakage-resistant CTIBench successor + a **risk-mitigation recommendation** task. Mini 750 open. |
| AttackSeqBench | 🟢 | ◻︎ | Reason about ATT&CK attack *sequences* (tactic/technique ordering) from reports. |
| 🆕 APTNER / AnnoCTR / AZERG / LANCE | 🟢 | ◻︎ | CTI entity/relation/IoC extraction sets named in Minerva-CTI's eval suite (arXiv 2602.00513) — leads to verify individually. |
| 🆕 Minerva-CTI | — | ✗ | 16 verifier-checkable CTI tasks, fully deterministic scoring — ideal shape, but it's a *training* suite with no public release. Watch for a drop. |

## 3. Malware Analysis / Reverse Engineering
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| CyberSOCEval — malware task | 🟢 | ✅ | Interpret sandbox detonation reports. *Already run.* |
| Malware behavior auditing ("Beyond Classification") | 🟢 | ◻︎ | Fine-grained behavior auditing from reports (dataset-based). |
| REBench / DecompileBench / CREBench / AgentRE-Bench | 🔴 | ◻︎ | Binary/decompiler reverse-engineering; need binaries + tooling. |

## 4. Vulnerability Management (CVE analysis)
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| **CTIBench-RCM** (CVE→CWE) | 🟢 | ⭐ | Map a CVE description to its root-cause CWE. 1,000 Q, exact-match. *Thesis leaf: 8B specialist reportedly beats GPT-5.* |
| CTIBench-VSP (CVSS) | 🟢 | ◻︎ | Predict CVSS severity vector/score from a description. 1,000 Q. |
| AthenaBench RCM / VSP | 🟢 | ◻︎ | Same tasks on fresh 2025 CVEs (2,000 each), contamination-resistant. |

## 5. Code Security / AppSec
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| VulDetectBench | 🟢 | ◻︎ | Is this function vulnerable? + which CWE type. 1,500 Q, exact-match. |
| PrimeVul (pairwise) | 🟢 | ◻︎ | Vuln vs patched twin — hardest modern detector (SOTA <12% pairwise). Big model separation. |
| DiverseVul / BigVul / CleanVul / SecVulEval | 🟢 | ◻︎ | Function-level vuln-detection datasets (labels, static scoring). |
| SecLLMHolmes | 🟡 | ◻︎ | Reasoning robustness (renaming/whitespace perturbations) — does it reason or pattern-match. |
| SecurityEval / LLMSecEval / CodeLMSec | 🟡 | ◻︎ | Secure code *generation* — does the model write vulnerable code (scored by Bandit/CodeQL). |
| VulRepair | 🟢 | ◻︎ | Auto-repair a vulnerable function; exact-match scoring (de-dup leakage first). |
| SecCodePLT / CVE-Bench (repair) / AutoPatchBench / CWE-Bench-Java | 🔴 | ◻︎ | Gen/detect/patch with test-execution or CodeQL builds. |
| 🆕 eyeballvul | 🟢 | ◻︎ | Vuln detection over real repo snapshots (arXiv 2407.08708). Public GitHub. |
| 🆕 SecureAgentBench / SafeGenBench / SecCodeBench-V2 | 🟡 | ◻︎ | Secure codegen + vuln detection in LLM-generated code (2025–26). Repos unverified. |

## 6. Detection Engineering
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| **Sigma Detection Classification** (cotool) | 🟢 | ⭐ | Given a Sigma rule (ATT&CK tags stripped) → output MITRE technique IDs. 2,733 rules, hierarchical F1. |
| 🆕 ElasticRule | 🟢 | ◻︎ | Elastic detection-rule → ATT&CK technique mapping (Sigma-task analogue; via Minerva-CTI eval suite). Verify repo. |
| CTI-REALM (Microsoft) | 🔴 | ◻︎ | Agent: CTI → telemetry → iterate KQL → emit validated Sigma rules + detections. |
| GenTI | 🟡 | ◻︎ | Generate IDPS + YARA signatures for unseen attacks; validated by rule compilers. |

## 7. Digital Forensics (DFIR)
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| DFIR-Metric — Module I | 🟢 | ◻︎ | Forensics knowledge MCQ (disk/memory/network, evidence handling). 700 Q. |
| DFIR-Metric — Modules II/III | 🔴 | ◻︎ | Hands-on forensic challenges over disk images. |
| NYU CTF / Cybench (forensics subsets) | 🔴 | ◻︎ | RE/forensics CTF challenges (cotool ran defensive subsets: 81 / 18). |

## 8. Offensive / Pentest / CTF / Exploitation
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| Cybench | 🔴 | ◻︎ | 40 pro CTF tasks in a Kali container. Frontier-lab standard; lightest credible offensive eval. |
| 3CB | 🔴 | ◻︎ | 15 "catastrophic capability" tasks, mapped to ATT&CK tactics. |
| AutoPenBench | 🔴 | ◻︎ | 33 end-to-end pentest tasks (recon→exploit→privesc), milestone-graded. |
| NYU CTF Bench | 🔴 | ◻︎ | 200 CTF challenges incl. binary-exploitation/pwn. Hardest well-adopted standard. |
| CVE-Bench (exploitation) | 🔴 | ◻︎ | 40 real web-app CVEs (CVSS ≥9), exploit-success verified. |
| ExploitBench | 🔴🔴 | ✗ | V8 exploitation, ~$80–200/episode, 70GB images, arm64-incompatible. *Ruled out — too heavy.* |
| Meta CyberSecEval offensive (static) | 🟡 | ◻︎ | Prompt-injection, spear-phishing, code-interpreter abuse — propensity, not real exploitation. |

## 9. Identity & Access (IAM) — ⚠️ coverage gap (confirmed again 2026-07-12)
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| *(no dedicated public benchmark)* | — | — | IAM shows up only *inside* BOTSv3 (AD/cloud auth Qs), Windows Enterprise Intrusion (AD attack), GOAD/Cochise (AD), and general knowledge MCQs. **Whitespace — candidate for a first-party eval.** |
| 🆕 Sola ISPM benchmarks ×2 (2026) | 🔴 | ✗ | ISPM visibility (77 Q, AWS/Okta/GWS) + cross-vendor (50 tasks, 8 platforms). Live vendor environment, expert+judge scoring, questions-only published — not reproducible. Their related work confirms OrgAccess is the only prior IAM benchmark → whitespace stands. |
| 🆕 IBACBench (DePLOI) | 🔴 | ◻︎ | NL policy → SQL GRANT synthesis + auditing (DB access control). Good model separation (F1 0.49–0.93) but no public artifact — reconstructable from Spider/BIRD/Amazon-Access. |
| 🆕 NLACBench (2026-06) | 🟢 | ◻︎ | NL/help-desk request → network access-control policy; auto-scored, strong separation (97% small nets → <20% large). Repo unverified. |

## 10. GRC / Compliance / Certifications
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| CyberCertBench | 🟢 | ◻︎ | Certification/standards exams (IEC 62443, Fortinet NSE, …). Still separates frontier models (unsaturated). |
| SECURE | 🟢 | ◻︎ | Real-world security *advisory* tasks (knowledge extraction, reasoning). |

## 11. General Security Knowledge (cross-domain MCQ)
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| CyberMetric | 🟢 | ◻︎ | Broad knowledge MCQ, 4 tiers (80/500/2k/10k). Cheap breadth baseline. |
| SecEval | 🟢 | ◻︎ | Security knowledge (OWASP/MITRE/CWE), ~2,100 MCQ, multi-select. |
| SecBench | 🟢 | ◻︎ | Largest MCQ set (~48k) + short-answer; bilingual. Sample it. |
| SecQA / MMLU-CompSec | 🟢 | ◻︎ | Small/standard sets — near-saturated; use as calibration/smoke only. |
| 🆕 RedSage-Bench | 🟢 | ◻︎ | 30k MCQ (lighteval-runnable) + 240 open QA (judge). Repo public; MCQ data release was pending — verify on HF. Side note: **RedSage-8B** (open Qwen3-8B security model) is a router *candidate model* for the specialist thesis. |

## 12. Safety / Dual-Use / Refusal (security-relevant)
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| WMDP-cyber | 🟢 | ◻︎ | Hazardous offensive-knowledge MCQ (high score = more dangerous capability). ~1,987 Q. |
| Meta CyberSecEval — FRR + MITRE | 🟡 | ◻︎ | Over-refusal on benign cyber asks vs willingness to assist offensive TTPs. |
| RedCode / HarmBench (cyber) | 🟡 | ◻︎ | Malicious-code-generation refusal / attack-success rate. |

## 13. LLM-App / Agent Security (prompt injection)
| Eval | Runnable | Status | What it tests |
|---|:--:|:--:|---|
| InjecAgent | 🟡 | ◻︎ | Indirect prompt injection in tool-using agents (1,054 cases). |
| AgentDojo | 🔴 | ◻︎ | Prompt injection in realistic tool workflows (70 tools, 97 tasks). |
| 🆕 Agent Security Bench (ASB) | 🟡 | ◻︎ | Formalizes attacks *and* defenses on LLM agents (2024-10). |
| 🆕 LLMail-Inject | 🟢 | ◻︎ | Dataset from a live adaptive prompt-injection challenge (2025-06). |
| 🆕 WAInjectBench | 🟡 | ◻︎ | Prompt-injection *detection* for web agents (2025-10). |
| 🆕 AgentThreatBench (UK AISI, 2026) | 🟡 | ◻︎ | OWASP Top-10 Agentic threats; ships via `inspect_evals`. |

---

### Quick read
- **Runnable today (🟢), highest value next:** CTIBench-RCM (vuln-mgmt / thesis leaf) + Sigma Detection Classification (detection engineering) — both cheap, both on the SOC-first path.
- **Covered so far:** malware analysis + CTI (CyberSOCEval).
- **Biggest gaps:** Identity/IAM (still no public reproducible benchmark — 2026 Sola/IBACBench activity confirms the gap rather than closing it; first-party opportunity stands), detection engineering (Sigma closes it), SOC-ops triage (only sandbox options — BOTSv3/ExCyTIn/SIABench).
- **Offensive (🔴):** all need a sandbox; start with Cybench when that phase comes, not ExploitBench.
- **⚠️ Contamination caution (2026):** offensive/CTF scores are heavily contamination-driven — under semantics-preserving obfuscation, zero-shot exploit success collapses to ~0%. Weight offensive rankings skeptically in the router; prefer leakage-resistant sets (AthenaBench) everywhere.
- **Whitespace partially closed elsewhere** (see UNIFIED_MAP): BEC (BEC-2 dataset, Fraud-R1), firewall/network config (NetConfEval — verified public, partially 🟢; Cornetto). CSPM/CNAPP and control→framework mapping remain open.
