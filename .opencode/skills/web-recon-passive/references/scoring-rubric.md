# Scoring rubric — severity × intel × architecture × confidence

## Finding fields (all five, always)

`severity` (analyst) + `cvss` (vector/score where applicable) +
`kev: true/false` + `epss` (percentile) + `confidence: high/medium/low` +
`verdict: exploitable/gated`, with one-line reasoning each.

## Priority order (defensible patch queue)

1. KEV-listed + exposed → NOW (exploited in the wild beats theory).
2. High EPSS + reachable → next.
3. High severity, non-KEV, reachable → scheduled.
4. Gated-but-scanner-flagged → later WITH explanation (architectural
   protection, reactivates if SSR/backend enabled — say so).
5. Informational → appendix, never the roadmap head.

Never rank a never-exploited high above a KEV-listed medium without
writing down why.

## Architecture × exposure matrix (cite the line per finding)

| Situation | Baseline |
|---|---|
| Clickjacking, brochure page, no forms | low |
| Clickjacking, working form with real data | medium |
| Clickjacking, authenticated settings | high |
| Missing HSTS, no login anywhere | low–medium (forms with PII raise it) |
| Missing HSTS, credentials handled | high |
| Weak email auth (SPF/DMARC), any org with clients | high (usually the top finding on small-business sites) |
| Server-side class (SQLi/RCE/SSRF/auth bypass) on static SPA | not a finding — architecturally impossible, say so |
| Gated CVE, SSR later possible | keep, label gated, explain reactivation |

## Confidence rules

- `high`: verbatim evidence + reachable path confirmed.
- `medium`: evidence real, one inference step (version confidence medium,
  single-bundle `signature-only`).
- `low`/`inconclusive`: heuristic only — report as uncertainty with the
  exact verification step, never as a verified negative or positive.

Recalibration must cite the matrix row and the target fact that moved it.
Severity reflects impact on THIS target, not generic CVSS.
