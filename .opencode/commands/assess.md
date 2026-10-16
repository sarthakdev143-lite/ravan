---
description: Start a security engagement with a structured intake. Asks ownership, scope, stack, and sensitivity, then writes the intake file. No scan starts without it.
agent: ravan
---

Run the guided intake for target `$TARGET` using the `question` tool. Ask and record:

1. Ownership proof (owner/operator with authority, or third-party → responsible-disclosure path).
2. Scope in/out (hosts, paths, what is explicitly excluded — third parties out by default).
3. Stack and architecture (static SPA / SSR / API / CMS) — determines what is even possible.
4. Data sensitivity (auth, PII, payments) — drives severity calibration.
5. Contact identity for User-Agent + report output directory.

Write results to `.opencode/security/intake-$TARGET.md`. Then state the authorization tier (passive-only now vs commissioned active-test plan later) and propose the next command (`/threat-model`, `/roe`, or direct assessment).
