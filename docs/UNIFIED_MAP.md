# Security Router — Unified Map (domain × task × benchmark × metric)

Run: 🟢 API · 🟡 API+judge/analyzer · 🔴 sandbox/infra.  Status: ✅ done · ⭐ next · ◻︎ candidate · ⬜ WHITESPACE (no benchmark).

## SOC / Incident Response
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| Report interpretation (MCQ) | CyberSOCEval | Jaccard (meanJac) | 🟢 | ✅ |
| Long-context log analysis | AuditBench (Google) | TPR/FPR/F1 | 🟢 | ◻︎ |
| Threat-hunting lifecycle | CyberTeam | F1 / acc / Hit@k | 🟢 | ◻︎ |
| IoC extraction | SEvenLLM | Entity-level F1 | 🟡 | ◻︎ |
| Alert triage / per-tactic detection | BOTSv3, Simbian | Precision/F1; recall-per-tactic | 🔴 | ◻︎ |
| Investigation Q&A | ExCyTIn-Bench | Exact-match accuracy | 🔴 | ◻︎ |

## Threat Intelligence (CTI)
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| Multi-select reasoning | CyberSOCEval-CTI | Jaccard | 🟢 | ✅ |
| Knowledge / attribution | CTIBench-MCQ | Accuracy | 🟢 | ◻︎ |
| ATT&CK technique extraction | CTIBench-ATE | Hierarchical multi-label F1 | 🟢 | ◻︎ |
| RAG-grounded CTI | CTIConnect | P/R/F1 + judge | 🟢 | ◻︎ |
| Multi-source reasoning | CTIArena | Accuracy + F1 | 🟡 | ◻︎ |
| Attack-sequence reasoning | AttackSeqBench | Accuracy | 🟢 | ◻︎ |

## Malware Analysis / RE
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| Report interpretation | CyberSOCEval-malware | Jaccard | 🟢 | ✅ |
| Behavior classification | behavior-audit set (2509.14335) | Macro-F1 | 🟢 | ◻︎ |
| Reverse engineering | REBench / DecompileBench | exact-match / edit-dist | 🔴 | ◻︎ |

## Vulnerability Management
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| CVE→CWE (root-cause map) | CTIBench-RCM | Exact-match acc (+hierarchical credit) | 🟢 | ⭐ |
| CVSS severity scoring | CTIBench-VSP | MAE/MAD + vector-component accuracy | 🟢 | ◻︎ |
| Leakage-resistant CTI/vuln | AthenaBench | Accuracy / F1 (fresh 2025 CVEs) | 🟢 | ◻︎ |
| Prioritization / ranking | custom (CISA KEV / EPSS) | NDCG, Precision@k | 🟢 | ◻︎ |

## Code Security / AppSec
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| Vuln detection (binary) | PrimeVul | VD-Score (FNR@≤0.5%FPR), **PR-AUC**, pairwise P-C | 🟢 | ◻︎ |
| Existence + CWE-type | VulDetectBench (T1/T2) | Accuracy / F1 | 🟢 | ◻︎ |
| Secure code generation | SecurityEval / CyberSecEval | Vulnerable-rate (secure@k) + functional-pass | 🟡 | ◻︎ |
| Vuln repair | VulRepair | Functional + security-check pass | 🟢 | ◻︎ |
| SAST false-positive triage | SastBench | Triage accuracy (agentic) | 🔴 | ◻︎ |

## Detection Engineering
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| Sigma → ATT&CK mapping | Sigma Detection Classif. (cotool) | Hierarchical multi-label F1 | 🟢 | ⭐ |
| Detection-rule generation | GenTI / CTI-REALM | Syntactic validity + detection efficacy | 🔴 | ◻︎ |

## DFIR
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| Forensics knowledge | DFIR-Metric (Module I) | Accuracy | 🟢 | ◻︎ |
| Log parse / anomaly / diagnosis | LogEval | F1 + AUC (standard, NOT point-adjusted) | 🟢 | ◻︎ |

## Cloud Security
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| IaC security generation | IaC-Eval / Multi-IaC-Eval | pass@1 + Checkov security pass | 🟢🟡 | ◻︎ |
| K8s misconfig detect/fix | GenKubeSec | Weighted P/R/F1 | 🟢 | ◻︎ |
| Terraform repair trust | TerraProbe | Deceptive-fix rate | 🔴 | ◻︎ |
| CSPM/CNAPP posture reasoning | — | — | — | ⬜ |

## Identity & Access (IAM)
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| RBAC / authz policy compliance | OrgAccess | F1 | 🟢 | ◻︎ |
| IAM policy comprehension/repair | Quacky (PolicySummarizer/CloudFix) | SMT model-counting ground truth | 🟡 | ◻︎ |
| ABAC policy mining | ABAC Lab | Policy-mining accuracy | 🟢 | ◻︎ |
| AD attack/defense reasoning | — | — | — | ⬜ |

## OT / ICS
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| OT/ICS knowledge | CyberCertBench (Fortinet/IEC 62443) | Exact accuracy (all-correct) | 🟢 | ◻︎ |
| Substation attack agent | CritBench | State-verification scoring | 🔴 | ◻︎ |

## Network Security
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| IDS/IPS rule generation | GenTI | Rule validity + detection efficacy | 🟡 | ◻︎ |
| PCAP forensic reasoning | RAG PCAP eval (Oprea) | Indicator-based grading | 🟢 | ◻︎ |
| Firewall/config security analysis | — | — | — | ⬜ |

## Data Security / DLP
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| PII detection / masking | PII-Bench / PIIBench | Span-level F1 (Strict-F1) | 🟢 | ◻︎ |
| Secret / credential detection | GitHub-issue secret-leak; CredData | P/R/F1; **MCC** | 🟢 | ◻︎ |
| Data-exfil via agents | Data-Leakage-in-Tool-Agents | Correctness&Safety pass rate | 🔴 | ◻︎ |

## GRC / Compliance
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| Certifications knowledge | CyberCertBench | Accuracy | 🟢 | ◻︎ |
| Data-protection law QA | LegiLM | LQA accuracy + justification quality | 🟡 | ◻︎ |
| Control → framework mapping (NIST/ISO/SOC2/PCI) | — (only EU-retrieval: EMERALD, nDCG@10) | — | — | ⬜ |

## Phishing / Social Engineering
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| Phishing webpage detection | PhreshPhish | F1 at realistic low base rates | 🟢 | ◻︎ |
| Phishing email (agentic) | PhishNChips | Deployability-aware composite | 🟢 | ◻︎ |
| Social-eng reasoning | Oslo/ELTE emotion set | Jaccard (multi-label) | 🟢 | ◻︎ |
| BEC detection | — | — | — | ⬜ |

## Insider Threat
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| Telemetry triage + verdict | OrgForge-IT | P/R/F1 + baseline FPR + attribution | 🟢* | ◻︎ |

## Offensive / CTF / Exploitation
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| CTF solving | Cybench / NYU CTF | Success-rate, pass@k, **subtask credit**, FST-difficulty | 🔴 | ◻︎ |
| Dangerous-capability | 3CB | Binary per-challenge (ATT&CK-mapped) | 🔴 | ◻︎ |
| Pentest lifecycle | AutoPenBench | Milestone / progress-rate | 🔴 | ◻︎ |
| Web-CVE exploitation | CVE-Bench | Exploit-success verified | 🔴 | ◻︎ |
| Exploit development | ExploitGym / ExploitBench | **Capability-ladder bitmap** | 🔴 | ✗ |
| Vuln discovery + patch | ZeroDayBench | Discover + patch-blocks-exploit | 🔴 | ◻︎ |
| Full kill-chain / lateral movement | AgentCyberRange | Root-blood, depth-stratified rate | 🔴 | ◻︎ |
| AI-vs-human pentest | ARTEMIS | Human-parity + cost ratio | 🔴 | ◻︎ |

## General Security Knowledge
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| Broad knowledge MCQ | CyberMetric / SecEval / SecBench | Accuracy | 🟢 | ◻︎ |

## Safety / Dual-Use
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| Malicious-request refusal | CyberSecEval-MITRE / StrongREJECT | ASR ↓ / graded score | 🟡 | ◻︎ |
| Over-refusal (benign) | CyberSecEval-FRR / XSTest / OR-Bench | FRR ↓ (paired on Pareto frontier) | 🟢 | ◻︎ |
| Hazardous knowledge | WMDP-cyber | Accuracy (inverted = risk) | 🟢 | ◻︎ |

## LLM-App / Agent Security
| Task | Benchmark | Metric | Run | St |
|---|---|---|:--:|:--:|
| Prompt injection | AgentDojo / InjecAgent | ASR under attack + task-utility | 🔴🟡 | ◻︎ |
| MCP tool-use security | MSB | Attack-taxonomy success rate | 🔴 | ◻︎ |
| AI-vs-AI (adversarial ML) | AIRTBench | CTF success | 🔴 | ◻︎ |

---
*OrgForge-IT leaderboard is Bedrock-only; harness runs via API. Cross-cutting quality controls (apply to all): **temporal/post-cutoff splits** for contamination; **cost / latency / reliability** as universal secondary axes; **calibration** (False Trust rate, AUGRC) for routing/hand-off decisions.
