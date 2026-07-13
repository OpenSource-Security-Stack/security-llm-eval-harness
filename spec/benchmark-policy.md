# Benchmark admission policy

A benchmark may go **live** on the leaderboard only if all of the following hold:

1. **Public artifact.** The dataset/tasks are publicly downloadable — a GitHub repo,
   HuggingFace dataset, or official data page. Papers alone don't qualify; "available on
   request" doesn't qualify.
2. **Verified link.** The artifact URL has been fetched and confirmed live, and is recorded in
   `spec/taxonomy.json` under the task's `source` field. The coverage map renders these links
   as credits.
3. **License permits our use.** Running models against the data and publishing aggregate
   scores must be allowed. Record the license id. If the license forbids redistribution, we
   link — never vendor — the data (that's the default anyway: `benchmarks/**/data/` is
   gitignored, each plugin documents its fetch command).
4. **Original source credited.** Credit the benchmark's authors/maintainers, not an
   aggregator or a reseller. If a benchmark derives from an upstream dataset (e.g. detection
   rules from SigmaHQ), credit the upstream too.
5. **Methodology faithful or documented.** Use the benchmark's canonical prompts/scoring
   where published; any deviation (subsetting, prompt changes) is stated on the leaderboard
   provenance line (e.g. "N=30 stratified subset").

Taxonomy entries that fail these checks stay `status: "candidate"` (never `live`) and carry
`source: null` or a note about what's missing. `NO-PUBLIC-ARTIFACT` benchmarks may be listed
in the coverage map as *gaps* ("no open benchmark exists here") — that's signal, not filler.

`source` field shape in `spec/taxonomy.json`:

```jsonc
"source": {
  "repo":  "https://github.com/...",      // and/or "data": HF/official data URL
  "paper": "https://arxiv.org/abs/...",   // optional
  "license": "MIT",                        // as shown by the artifact
  "verified": "2026-07-13"                 // date the links were last fetched
}
```
