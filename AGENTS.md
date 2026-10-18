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
- Calibrate per target: `scripts/calibrate.py` pre-suppresses FPs and adjusts
  checks. Post-assessment: `scripts/trend.py` computes posture timeline.

## Agent team

- `@ravan-recon` — passive recon, returns JSON facts.
- `@ravan-reviewer` — read-only code review.
- `@ravan-reporter` — finding JSON → enforced report.
- `@ravan-verifier` — re-runs checks post-remediation, diffs evidence, closes loop.
- `@ravan-scout` — pre-authorized active scanners (Nuclei safe, Semgrep).
- `@ravan-handoff` — stakeholder artifacts (dev fix, exec summary, auditor).

## Engine scripts (all writes go through these)

- `engine/policy_check.py <host> <tier>` — authorization gate (enforced in code)
- `engine/ledger_append.py --json ...` — append validated findings (subagents use this)
- `engine/scout_run.py --target ... --scanner nuclei` — active scanner with scope enforcement
- `engine/safe_write.py <path>` — validate --out path before writing
- `engine/doctor.py` — tool audit + preflight; `--required-only` for missing tools
- `engine/gate.py [--target X] [--push]` — completion gate; exit 2 = keep working
- `engine/leads.py add/list/explore/close/summary` — discovered-but-unexplored pathways
- `db/ravan.py init/import-jsonl/findings/chains/session` — SQLite findings DB

## Tiered active mode

- `.opencode/security/policies/<host>.json` per target authorizes tiers.
- Create: `python3 engine/policy_check.py <host> 1 --create-default` then edit.
- Tier 0 (passive): always. Tier 1 (safe active): policy-gated. Tier 2/3: operator-draft.
- `scout_run.py` calls `policy_check.py` — scope + expiry + tier enforced in code.

## No-escape mode

- Single auth question, then full pipeline: recon + scout + review + report + handoff.
- Asks once for missing tools (doctor.py). Never installs without user confirmation.
- Gate blocks completion until all leads closed + all findings verdicted + report exists.

## Tool budgets

- Passive runs: max 400 requests, ≥0.7s delay, real `--contact` identity.
- Tier 1 active: max 1000 requests, scoped to declared target + scope.included only.
- Shell: ask-by-default; specific exact-path scripts allowed (no globs).

## Completion gate

- Run `engine/gate.py --push` whenever the agent thinks it's done.
- Gate FAIL = keep working. Time exhaustion = change strategy, not stop.
- Nothing discovered is abandoned — every lead goes in `engine/leads.py`.
- Session log every tool run: `db/ravan.py session log --agent X --tool Y ...`

## Skill hygiene

- stdlib-only Python, no pip installs. Offline tests must pass:
  `python scripts/test_checks.py` (+ `enrich.py --selftest`).
- New `checks.py` pattern ⇒ new `test_checks.py` fixture proving it does
  not fire on react-dom.
