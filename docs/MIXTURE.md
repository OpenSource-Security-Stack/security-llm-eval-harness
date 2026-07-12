# Mixture-of-Open-Models Analysis

_Offline aggregation of cached per-question answers (results/*_merged7.jsonl). No new API calls. Same Jaccard scoring as the harness. N=30/task — directional, not final._

## Malware Analysis  (N=30 questions)

### Single models (reference)

| Model | exact% | meanJac | answered% | $/1k Q |
|---|--:|--:|--:|--:|
| opus-4.8 *(closed)* | 30.0% | 0.601 | 100% | $295.44 |
| gpt-5.5 *(closed)* | 30.0% | 0.582 | 97% | $19.57 |
| minimax-m3 | 23.3% | 0.527 | 87% | $7.59 |
| qwen3-235b | 23.3% | 0.516 | 93% | $2.73 |
| glm-5.2 | 16.7% | 0.445 | 80% | $45.10 |
| gpt-oss-120b | 23.3% | 0.542 | 93% | $2.33 |

### Mixtures of open-weight models

| Mixture | rule | exact% | meanJac | answered% | $/1k Q | vs gpt-5.5 meanJac | $ vs gpt-5.5 |
|---|---|--:|--:|--:|--:|--:|--:|
| OSS-3 (minimax+qwen+glm) | majority | 23.3% | 0.553 | 93% | $55.42 | -0.029 | 2.83× |
| OSS-3 (minimax+qwen+glm) | weighted | 23.3% | 0.536 | 93% | $55.42 | -0.046 | 2.83× |
| OSS-3 (minimax+qwen+glm) | union | 13.3% | 0.489 | 93% | $55.42 | -0.092 | 2.83× |
| OSS-3 (minimax+qwen+glm) | intersect | 26.7% | 0.511 | 93% | $55.42 | -0.071 | 2.83× |
| OSS-4 (+gpt-oss-120b) | majority | 16.7% | 0.509 | 93% | $57.74 | -0.073 | 2.95× |
| OSS-4 (+gpt-oss-120b) | weighted | 26.7% | 0.565 | 93% | $57.74 | -0.017 | 2.95× |
| OSS-4 (+gpt-oss-120b) | union | 13.3% | 0.489 | 93% | $57.74 | -0.092 | 2.95× |
| OSS-4 (+gpt-oss-120b) | intersect | 23.3% | 0.477 | 93% | $57.74 | -0.104 | 2.95× |

### Threshold-k sweep (letter kept if ≥k members pick it)

- **OSS-3 (minimax+qwen+glm)**  ·  k=1: Jac 0.489/ex 13%  ·  k=2: Jac 0.503/ex 20%  ·  k=3: Jac 0.441/ex 23%
- **OSS-4 (+gpt-oss-120b)**  ·  k=1: Jac 0.489/ex 13%  ·  k=2: Jac 0.509/ex 17%  ·  k=3: Jac 0.511/ex 23%  ·  k=4: Jac 0.407/ex 20%

### Oracle upper bounds (NOT deployable — ceiling for a perfect per-question router)

| Pool | any-member-exact % | best-member meanJac |
|---|--:|--:|
| OSS-3 (minimax+qwen+glm) | 33.3% | 0.636 |
| OSS-4 (+gpt-oss-120b) | 33.3% | 0.636 |

> **Verdict (Malware Analysis):** best mixture = *OSS-4 (+gpt-oss-120b) · weighted* at meanJac **0.565** vs gpt-5.5 **0.582** → does NOT match. Mixture answered 93% (reliability), cost $57.74/1k vs gpt-5.5 $19.57/1k.

## Threat-Intel Reasoning  (N=30 questions)

### Single models (reference)

| Model | exact% | meanJac | answered% | $/1k Q |
|---|--:|--:|--:|--:|
| opus-4.8 *(closed)* | 66.7% | 0.750 | 100% | $227.06 |
| gpt-5.5 *(closed)* | 60.0% | 0.700 | 100% | $14.17 |
| minimax-m3 | 60.0% | 0.722 | 100% | $3.51 |
| qwen3-235b | 56.7% | 0.684 | 100% | $1.95 |
| glm-5.2 | 66.7% | 0.722 | 90% | $29.99 |
| gpt-oss-120b | 56.7% | 0.672 | 97% | $1.60 |

### Mixtures of open-weight models

| Mixture | rule | exact% | meanJac | answered% | $/1k Q | vs gpt-5.5 meanJac | $ vs gpt-5.5 |
|---|---|--:|--:|--:|--:|--:|--:|
| OSS-3 (minimax+qwen+glm) | majority | 63.3% | 0.744 | 100% | $35.45 | +0.044 | 2.50× |
| OSS-3 (minimax+qwen+glm) | weighted | 63.3% | 0.731 | 100% | $35.45 | +0.031 | 2.50× |
| OSS-3 (minimax+qwen+glm) | union | 50.0% | 0.684 | 100% | $35.45 | -0.016 | 2.50× |
| OSS-3 (minimax+qwen+glm) | intersect | 60.0% | 0.700 | 100% | $35.45 | +0.000 | 2.50× |
| OSS-4 (+gpt-oss-120b) | majority | 60.0% | 0.736 | 100% | $37.06 | +0.036 | 2.61× |
| OSS-4 (+gpt-oss-120b) | weighted | 66.7% | 0.764 | 100% | $37.06 | +0.064 | 2.61× |
| OSS-4 (+gpt-oss-120b) | union | 50.0% | 0.688 | 100% | $37.06 | -0.012 | 2.61× |
| OSS-4 (+gpt-oss-120b) | intersect | 60.0% | 0.694 | 100% | $37.06 | -0.006 | 2.61× |

### Threshold-k sweep (letter kept if ≥k members pick it)

- **OSS-3 (minimax+qwen+glm)**  ·  k=1: Jac 0.684/ex 50%  ·  k=2: Jac 0.736/ex 63%  ·  k=3: Jac 0.678/ex 60%
- **OSS-4 (+gpt-oss-120b)**  ·  k=1: Jac 0.688/ex 50%  ·  k=2: Jac 0.736/ex 60%  ·  k=3: Jac 0.689/ex 60%  ·  k=4: Jac 0.650/ex 57%

### Oracle upper bounds (NOT deployable — ceiling for a perfect per-question router)

| Pool | any-member-exact % | best-member meanJac |
|---|--:|--:|
| OSS-3 (minimax+qwen+glm) | 70.0% | 0.794 |
| OSS-4 (+gpt-oss-120b) | 70.0% | 0.794 |

> **Verdict (Threat-Intel Reasoning):** best mixture = *OSS-4 (+gpt-oss-120b) · weighted* at meanJac **0.764** vs gpt-5.5 **0.700** → MATCHES/BEATS. Mixture answered 100% (reliability), cost $37.06/1k vs gpt-5.5 $14.17/1k.