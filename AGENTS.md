# Ravan project conventions (auto-loaded every session)

## Security workflow

- No scan without intake: `/assess` first (`.opencode/security/intake-*.md`).
- Reports go to `reports/<target>/` as `<host>-<date>.json` + `.md`.
- Findings append to `.opencode/security/findings.jsonl` (schema header line
  is the format contract). Check `.opencode/security/suppressions.md`
  before flagging anything.
- Severity follows `scoring-rubric.md` (KEV/EPSS/confidence/verdict on every
  finding). Recalibration cites the rubric line + target fact.
- Retests go through `/retest <finding-id>`; baselines diff via
  `scripts/diff.py`. Enrich CVEs via `scripts/enrich.py` (cached, offline-safe).

## Tool budgets

- Passive runs: max 400 requests, ≥0.7s delay, real `--contact` identity.
- Shell is ask-by-default; allowlisted recon/git/npm/python-scripts only.
- Active scanners stay denied — draft operator commands, never execute.

## Skill hygiene

- stdlib-only Python, no pip installs. Offline tests must pass:
  `python scripts/test_checks.py` (+ `enrich.py --selftest`).
- New `checks.py` pattern ⇒ new `test_checks.py` fixture proving it does
  not fire on react-dom.
