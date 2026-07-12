# Security Landscape — Master Map (domains × tasks × tools × people)

Organized by the **NIST Cybersecurity Framework** functions (Govern / Identify / Protect /
Detect / Respond / Recover), plus Offense (spans the attacker lifecycle) and AI-native domains.
Companion to `EVAL_MAP.md` (which benchmark tests which domain).

---

## GOVERN — run security responsibly
| Domain | Core tasks | Key tools / tech | People |
|---|---|---|---|
| **GRC** | Risk assessment (identify→assess→treat), policy, compliance mapping (ISO 27001 / SOC 2 / PCI-DSS / NIST CSF), audit, security awareness | Archer, ServiceNow GRC, Vanta, Drata; risk registers | GRC Analyst, Compliance Manager, Risk Analyst, Auditor, **CISO** |

## IDENTIFY — know your assets and weaknesses
| Domain | Core tasks | Key tools / tech | People |
|---|---|---|---|
| **Asset & Attack-Surface Mgmt** | Inventory assets, discover external exposure | CMDB, ASM (Censys, runZero) | Security Engineer |
| **Vulnerability Management** | Scan → triage with CVSS/EPSS/KEV → prioritize → remediate → verify | Nessus, Qualys, Tenable; EPSS, CISA KEV | Vulnerability Analyst/Engineer |

## PROTECT — build the walls
| Domain | Core tasks | Key tools / tech | People |
|---|---|---|---|
| **Identity & Access (IAM)** | AuthN (MFA/passwordless/FIDO2), AuthZ (RBAC/ABAC, least privilege), PAM, joiner/mover/leaver lifecycle, SSO/federation (SAML/OIDC) | Okta, Entra ID / Active Directory, Ping; CyberArk (PAM) | IAM Engineer, Identity Architect |
| **Data Security & DLP** | Classification, encryption at rest/in transit/in use, key mgmt, masking/tokenization, DLP enforcement, data discovery | DLP (Purview, Forcepoint), DSPM (Cyera, Varonis), CASB, KMS/HSM | Data Security Engineer, Privacy Engineer / DPO |
| **Application Security** | Threat modeling, **SAST / DAST / IAST / SCA**, secrets scanning, secure SDLC/CI gates | Semgrep, CodeQL, Checkmarx (SAST); Burp, ZAP (DAST); Snyk (SCA) | AppSec / Product Security Engineer |
| **Security Architecture & Network** | Segmentation, **Zero Trust / ZTNA**, **SASE**, firewall/proxy design, secure-by-design review | Palo Alto, Zscaler, Netskope; NGFWs | Security Architect, Network Security Engineer |
| **Cloud Security** | Misconfig (CSPM), workload protection (CWPP), cloud entitlements (CIEM), IaC scanning | Wiz, Prisma Cloud, Orca (CNAPP) | Cloud Security Engineer |

## DETECT — watch for trouble
| Domain | Core tasks | Key tools / tech | People |
|---|---|---|---|
| **Detection Engineering** | Author/tune detection rules (**Sigma/YARA/Snort**), ATT&CK coverage mapping, detections-as-code, false-positive reduction | Sigma, YARA, Suricata; detection-as-code repos | Detection Engineer |
| **Security Monitoring (SOC)** | Alert triage (L1/L2), correlation, escalation | SIEM (Splunk, Sentinel, Elastic), SOAR, EDR/XDR | SOC Analyst L1 / L2 |
| **Threat Hunting** | Hypothesis-driven proactive search for undetected threats | EDR/XDR, SIEM, threat intel | Threat Hunter |
| **Threat Intelligence (CTI)** | Actor tracking, IoC/TTP analysis, ATT&CK mapping, intel reporting | MISP, threat feeds, MITRE ATT&CK | CTI Analyst |

## RESPOND / RECOVER — react and rebuild
| Domain | Core tasks | Key tools / tech | People |
|---|---|---|---|
| **Incident Response** | Contain → eradicate → recover, IR lifecycle (NIST 800-61), comms | EDR response, SOAR, IR playbooks | Incident Responder (L3), IR Lead |
| **Digital Forensics (DFIR)** | Disk/memory/network/cloud forensics, chain of custody, timeline reconstruction | Volatility, Autopsy, EnCase, Velociraptor | Forensic Analyst / Examiner |
| **Malware Analysis / RE** | Static → dynamic → reverse engineering; extract indicators + signatures | Ghidra, IDA Pro; sandboxes (ANY.RUN, Cuckoo) | Malware Analyst / Reverse Engineer |
| **Recovery / BC-DR** | Backups, disaster recovery, restoration | Backup/DR systems | Resilience / BC-DR roles |

## OFFENSE — test the whole thing (spans the attacker kill chain)
| Domain | Core tasks | Key tools / tech | People |
|---|---|---|---|
| **Pentest / Red Team / Exploitation** | Recon → exploit → privesc → lateral movement; red teaming (stealth, goal-driven), purple teaming | Kali, Metasploit, Cobalt Strike, Burp, nmap | Penetration Tester, Red Teamer, Exploit Developer |

## AI-NATIVE — because the analyst is now a model
| Domain | Core tasks | Key tools / tech | People |
|---|---|---|---|
| **Safety / Dual-Use** | Refuse malicious cyber asks without over-refusing legit security work | Eval harnesses (CyberSecEval FRR, WMDP) | AI Safety / Security Researcher |
| **LLM-App / Agent Security** | Prompt-injection defense, agent guardrails, AI red-teaming | Guardrails, AI firewalls | AI Security Engineer |

---

## Leadership spanning all
**CISO** (owns the whole program) → Security Directors → Engineering Managers → the specialist
roles above. Generalist **Security Engineer** roles bridge several domains at smaller orgs.

## Tool/architecture glossary (where the acronyms live)
- **EDR/XDR/NDR** (endpoint/extended/network detection & response), **SIEM/SOAR** → Detect + Respond
- **MDR** = the SOC *outsourced as a managed service*
- **SAST/DAST/IAST/SCA** → Application Security (the four ways to test an app)
- **SASE / ZTNA**, **Zero Trust** → Security Architecture + IAM
- **DLP / DSPM / CASB**, **KMS/HSM**, **PAM** → Data Security + IAM
- **CSPM / CWPP / CIEM / CNAPP** → Cloud Security
