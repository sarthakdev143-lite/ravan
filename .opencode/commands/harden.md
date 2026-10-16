---
description: Hardening plan for an area (CSP, HSTS, cookies, CORS, TLS, email-auth, framework defaults). Plan-first with blast-radius warnings, exact configs, staged rollout.
agent: ravan
---

Plan hardening for `$AREA` on `$TARGET`.

1. Plan in a denied-edits pass first: current state, target state, blast radius (e.g. HSTS `includeSubDomains` breaks insecure subdomains, CSP enforce breaks inline scripts, SPF `-all` / DMARC `p=reject` drop mail).
2. Give exact copy-pasteable blocks from `references/hardening-matrix.md` for the target stack, with staged rollout order (report-only → enforce, 300 → 86400 → 31536000, monitor → quarantine → reject) and rollback per stage.
3. End with a verification checklist (owner-runnable commands) and what to monitor post-change. Never prescribe an irreversible step (preload submission) without the reversibility warning.
