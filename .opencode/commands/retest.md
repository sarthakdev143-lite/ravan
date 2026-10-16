---
description: Re-verify a single finding by ID. Re-runs only its checks, compares evidence, marks fixed, persists, or regressed in the ledger.
agent: ravan
---

Retest finding `$FINDING_ID`.

1. Load the finding from `.opencode/security/findings.jsonl` (evidence, check, target).
2. Re-run ONLY the checks covering that finding (same tool, same budget discipline). Compare new evidence vs recorded evidence.
3. Update the ledger: `fixed` (evidence gone + verification command passes), `persists` (evidence unchanged), or `regressed` (fixed then reappeared). Report the verdict with fresh verbatim evidence. Never mark fixed on missing data — absence of signal is not evidence of security.
