---
description: No-escape mode — proactive vulnerability hunting with safe active checks for owned targets.
---

# /no-escape — proactive threat hunting

You've asked Ravan to hunt proactively. This mode runs the full pipeline:
passive recon + safe active scanning (Nuclei + Semgrep) + cross-referencing.

## Authorization

Ravan will ask **once** to confirm you own the target and authorize safe active
checks. If yes, it creates an `active-policy.json` with Tier 0 + Tier 1
enabled for 24 hours.

## What runs

| Phase | Agent | What it does |
|---|---|---|
| 1 | `@ravan-recon` | Full passive recon — DNS, TLS, headers, JS bundles, CVE correlation |
| 2 | `@ravan-scout` | Nuclei safe templates (cves/exposure/misconfig/tech) + Semgrep SAST |
| 3 | Orchestrator | Cross-reference, deduplicate, re-rank all findings |
| 4 | `@ravan-reporter` | Full report with enforced template |
| 5 | `@ravan-handoff` | Stakeholder artifacts — dev fix guide, exec summary, auditor evidence |

## Missing tools

If `nuclei` or `semgrep` is not installed, Ravan will ask once whether to
install it or have you run it manually. It never installs without asking.

## Constraints

- Tier 2 (intrusive) and Tier 3 (destructive) are never auto-run — they are
  drafted as operator procedures.
- The scan stops if the target shows signs of distress (5xx storms, WAF blocks).
- Third-party infrastructure is always out of scope.
