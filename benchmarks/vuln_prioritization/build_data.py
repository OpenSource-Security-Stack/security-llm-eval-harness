"""Build a FROZEN, reproducible snapshot of vuln-prioritization ranking questions.

Sources (all free, no API key):
  - CISA KEV JSON (CC0)         -> high-risk CVEs, descriptions, KEV membership
  - FIRST.org EPSS API (attrib) -> exploitation-probability score per CVE
  - NVD CVE API 2.0             -> descriptions for low-EPSS (non-KEV) distractor CVEs

Output: data/questions.json  (see SCHEMA in bench.py). Deterministic given the
frozen kev.json + the fixed RNG seed. This script is a one-time builder; the
harness never calls it (it reads the frozen questions.json).

Run once from the repo root:
    python3 benchmarks/vuln_prioritization/build_data.py
"""
import json
import random
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
KEV_JSON = DATA / "kev.json"
OUT = DATA / "questions.json"

SEED = 1729
N_QUESTIONS = 60
CVES_PER_Q = 15
N_HIGH_PER_Q = 5          # KEV / high-EPSS CVEs per question (rest are low-risk)
KEV_POOL = 400            # how many KEV CVEs to draw the high-risk pool from
LOW_POOL = 400            # how many low-EPSS non-KEV CVEs to gather

UA = {"User-Agent": "vuln-prio-benchmark/1.0 (security-llm-eval-harness)"}


def _get(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def epss_bulk(cves):
    """cve -> float epss, batched (EPSS allows comma-separated, limit ~100)."""
    out = {}
    for i in range(0, len(cves), 90):
        chunk = cves[i:i + 90]
        q = urllib.parse.quote(",".join(chunk))
        d = _get(f"https://api.first.org/data/v1/epss?cve={q}&limit=100")
        for row in d.get("data", []):
            out[row["cve"]] = float(row["epss"])
        time.sleep(0.4)
    return out


def epss_lowest(n):
    """The n CVEs with the LOWEST EPSS in the universe (ascending order)."""
    out = []
    per = 200
    for off in range(0, n, per):
        d = _get(f"https://api.first.org/data/v1/epss?order=epss&limit={per}&offset={off}")
        out.extend(d.get("data", []))
        time.sleep(0.4)
    return [(r["cve"], float(r["epss"])) for r in out[:n]]


def nvd_desc(cve):
    """English description from NVD 2.0 for one CVE, or None. Rate-limited."""
    try:
        d = _get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}")
        v = d["vulnerabilities"][0]["cve"]
        for x in v["descriptions"]:
            if x["lang"] == "en":
                return x["value"].strip()
    except Exception as e:
        print(f"  nvd miss {cve}: {e}")
    return None


def main():
    rng = random.Random(SEED)
    kev = json.loads(KEV_JSON.read_text())
    kev_vulns = kev["vulnerabilities"]

    # ---- high-risk pool: KEV CVEs (deterministic sort, then sample) ----------
    kev_sorted = sorted(kev_vulns, key=lambda v: v["cveID"])
    kev_pool = kev_sorted[:KEV_POOL]
    kev_ids = [v["cveID"] for v in kev_pool]
    print(f"KEV pool: {len(kev_ids)} CVEs; fetching EPSS...")
    kev_epss = epss_bulk(kev_ids)

    high = {}
    for v in kev_pool:
        cid = v["cveID"]
        desc = (v.get("shortDescription") or v.get("vulnerabilityName") or "").strip()
        if not desc:
            continue
        high[cid] = {
            "cve": cid, "desc": desc,
            "epss": kev_epss.get(cid, 0.0),
            "kev": True,
        }
    print(f"high-risk usable: {len(high)}")

    # ---- low-risk pool: lowest-EPSS non-KEV CVEs, descriptions from NVD ------
    kev_id_set = {v["cveID"] for v in kev_vulns}
    print("fetching lowest-EPSS universe...")
    low_candidates = [(c, e) for c, e in epss_lowest(LOW_POOL) if c not in kev_id_set]
    # deterministic order
    low_candidates.sort(key=lambda t: (t[1], t[0]))

    low = {}
    need = N_QUESTIONS * (CVES_PER_Q - N_HIGH_PER_Q) // 3  # gather a generous pool
    need = max(need, 220)
    print(f"fetching NVD descriptions for up to {min(len(low_candidates), need)} low-EPSS CVEs...")
    for cid, e in low_candidates:
        if len(low) >= need:
            break
        desc = nvd_desc(cid)
        time.sleep(0.7)  # NVD unauthenticated rate limit (~5/30s -> be gentle)
        if not desc:
            continue
        low[cid] = {"cve": cid, "desc": desc, "epss": e, "kev": False}
        if len(low) % 20 == 0:
            print(f"  low collected: {len(low)}")
    print(f"low-risk usable: {len(low)}")

    high_ids = sorted(high)
    low_ids = sorted(low)
    if len(high_ids) < N_HIGH_PER_Q or len(low_ids) < (CVES_PER_Q - N_HIGH_PER_Q):
        raise SystemExit("not enough usable CVEs to build questions")

    # ---- assemble questions deterministically --------------------------------
    questions = []
    for qi in range(N_QUESTIONS):
        h = rng.sample(high_ids, N_HIGH_PER_Q)
        l = rng.sample(low_ids, CVES_PER_Q - N_HIGH_PER_Q)
        chosen = h + l
        rng.shuffle(chosen)  # presentation order is shuffled; ranking is the task
        items, gains = [], {}
        for cid in chosen:
            rec = high.get(cid) or low[cid]
            gain = 1.0 if rec["kev"] else round(rec["epss"], 6)
            items.append({"cve": cid, "desc": rec["desc"],
                          "epss": round(rec["epss"], 6), "kev": rec["kev"]})
            gains[cid] = gain
        questions.append({
            "qid": f"vprio-{qi:03d}",
            "cves": items,
            "gains": gains,
        })

    OUT.write_text(json.dumps({
        "meta": {
            "seed": SEED, "n_questions": N_QUESTIONS,
            "cves_per_question": CVES_PER_Q, "high_per_question": N_HIGH_PER_Q,
            "kev_source": "CISA KEV (CC0)",
            "epss_source": "FIRST.org EPSS API",
            "desc_source_low": "NVD CVE API 2.0",
            "gain_def": "KEV -> 1.0, else EPSS score in [0,1]",
            "epss_date": kev_epss and "see FIRST.org snapshot date",
        },
        "questions": questions,
    }, indent=1))
    print(f"wrote {OUT} with {len(questions)} questions")


if __name__ == "__main__":
    main()
