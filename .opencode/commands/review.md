---
description: Secure code review of current changes or given paths. Read-only taint analysis with file-line evidence and exploitability verdicts.
agent: ravan
---

Review `$PATHS` (default: current diff) for security flaws.

1. Delegate the read-only pass to `@ravan-reviewer` with stack + trust boundaries.
2. Re-rank results: confirm taint reaches a sink, apply `references/scoring-rubric.md`, check suppressions in `.opencode/security/suppressions.md` before flagging.
3. Report: file:line findings with verdict (`exploitable`/`gated`) + confidence + one exact fix each, coverage note (reviewed vs not), and what needs runtime/DAST. Append confirmed findings to `.opencode/security/findings.jsonl`.
