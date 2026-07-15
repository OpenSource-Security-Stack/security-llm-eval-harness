# Security LLM Evals — v0 Model Comparison

**Leaves:** `malware.sandbox_interpretation`, `cti.ti_reasoning` (CyberSOCEval). **N = 30 questions/leaf**, 7 models. Scoring = Jaccard over multi-select letters (PurpleLlama methodology). CTI = CrowdStrike-only subset.

> ⚠️ **N=30 is a smoke sample** — meanJac gaps < ~0.05 and exact% ties are within noise. Read cost/latency/reliability as robust; treat fine quality ranks as provisional.

## 1. Models & pricing

| Model | Type | Provider | $/1M in | $/1M out |
|---|---|---|--:|--:|
| `opus-4.8` | frontier closed (Anthropic) | anthropic | $15.00 | $75.00 |
| `gpt-5.5` | frontier closed (newer) | openai | $1.25 | $10.00 |
| `gpt-5.1` | frontier closed | openai | $1.25 | $10.00 |
| `glm-5.2` | OSS reasoning (Zhipu) | together | $1.40 | $4.40 |
| `minimax-m3` | OSS reasoning (MiniMax) | together | $0.30 | $1.20 |
| `qwen3-235b` | OSS MoE 235B (Alibaba) | together | $0.20 | $0.60 |
| `gpt-oss-120b` | OSS 120B (OpenAI open-weights) | together | $0.15 | $0.60 |

_Together prices pulled live from its API; gpt-5.1 confirmed $1.25/$10 per 1M. ⚠️ gpt-5.5 (= gpt-5.1) and opus-4.8 ($15/$75 std Opus tier) prices are PLACEHOLDERS — confirm their real rates to trust those $ columns._

## 2. Benchmark — `malware.sandbox_interpretation`

| Model | exact% | meanJac | parse✓ | latency | in tok/q | out tok/q | $/1k Q | $/correct |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `opus-4.8` | 30.0% | 0.601 | 100% | 2.5s | 19260 | 87 | $295.44 | $0.9848 |
| `gpt-5.5` | 30.0% | 0.582 | 100% | 8.2s | 12463 | 399 | $19.57 | $0.0652 |
| `gpt-5.1` | 16.7% | 0.543 | 100% | 1.1s | 12463 | 28 | $15.86 | $0.0952 |
| `gpt-oss-120b` | 23.3% | 0.542 | 100% | 6.5s | 12524 | 745 | $2.33 | $0.0100 |
| `minimax-m3` | 23.3% | 0.527 | 90% | 18.8s | 12516 | 3197 | $7.59 | $0.0325 |
| `qwen3-235b` | 23.3% | 0.516 | 100% | 1.6s | 13591 | 18 | $2.73 | $0.0117 |
| `glm-5.2` | 16.7% | 0.445 | 80% | 31.7s | 12426 | 6296 | $45.10 | $0.2706 |

## 2. Benchmark — `cti.ti_reasoning`

| Model | exact% | meanJac | parse✓ | latency | in tok/q | out tok/q | $/1k Q | $/correct |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `opus-4.8` | 66.7% | 0.750 | 100% | 2.2s | 14950 | 38 | $227.06 | $0.3406 |
| `gpt-5.1` | 66.7% | 0.739 | 100% | 1.6s | 9063 | 25 | $11.58 | $0.0174 |
| `glm-5.2` | 66.7% | 0.722 | 90% | 26.0s | 9168 | 3899 | $29.99 | $0.0450 |
| `minimax-m3` | 60.0% | 0.722 | 100% | 9.9s | 9133 | 641 | $3.51 | $0.0058 |
| `gpt-5.5` | 60.0% | 0.700 | 100% | 6.0s | 9063 | 284 | $14.17 | $0.0236 |
| `qwen3-235b` | 56.7% | 0.684 | 100% | 1.4s | 9693 | 18 | $1.95 | $0.0034 |
| `gpt-oss-120b` | 56.7% | 0.672 | 100% | 2.8s | 9124 | 394 | $1.60 | $0.0028 |

## 3. Cross-leaf quality (meanJac) & the reshuffle

| Model | malware | CTI | avg | malware rank | CTI rank |
|---|--:|--:|--:|:-:|:-:|
| `opus-4.8` | 0.601 | 0.750 | 0.676 | 1 | 1 |
| `gpt-5.5` | 0.582 | 0.700 | 0.641 | 2 | 5 |
| `gpt-5.1` | 0.543 | 0.739 | 0.641 | 3 | 2 |
| `minimax-m3` | 0.527 | 0.722 | 0.625 | 5 | 4 |
| `gpt-oss-120b` | 0.542 | 0.672 | 0.607 | 4 | 7 |
| `qwen3-235b` | 0.516 | 0.684 | 0.600 | 6 | 6 |
| `glm-5.2` | 0.445 | 0.722 | 0.583 | 7 | 3 |

## 4. Cost-efficiency ($/correct answer)

| Model | malware $/correct | CTI $/correct |
|---|--:|--:|
| `opus-4.8` | $0.9848 | $0.3406 |
| `gpt-5.5` | $0.0652 | $0.0236 |
| `gpt-5.1` | $0.0952 | $0.0174 |
| `glm-5.2` | $0.2706 | $0.0450 |
| `minimax-m3` | $0.0325 | $0.0058 |
| `qwen3-235b` | $0.0117 | $0.0034 |
| `gpt-oss-120b` | $0.0100 | $0.0028 |
