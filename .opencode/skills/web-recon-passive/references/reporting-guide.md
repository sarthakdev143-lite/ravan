# Reporting Guide

How to turn scan output into a report someone will act on.

## The core discipline

A finding is a claim. Every claim needs verbatim evidence, a mechanism, an impact expressed
in the target's terms, and a specific fix. If you cannot supply all four, it is not a
finding — it is an observation, and should be labelled as one.

**Evidence must be copy-pasteable.** Not "several security headers are missing" but
`X-Content-Type-Options: absent (observed on GET /, 2026-10-15)`. The reader should be able
to reproduce every claim with one command.

## Severity calibration

Baseline severities from the tool are a starting point. Adjust to the actual target and
**state that you adjusted it and why** — silent recalibration looks like inconsistency.

| Severity | Meaning | Test to apply |
|---|---|---|
| Critical | Exploitable now → compromise or data loss | Can an attacker own the system or read other users' data today? |
| High | Exploitable now, real business impact | Can an attacker cause concrete harm without preconditions? |
| Medium | Weakens a control meaningfully, or needs preconditions | Does this make a plausible attack substantially easier? |
| Low | Hardening gap, defence-in-depth, hygiene | Would you fix it this quarter? |
| Info | Context; no action strictly required | Does it change how other findings should be read? |

Two calibration traps in particular:

**Under-rating email authentication.** `p=none` DMARC with no DKIM is a DNS record, so it
reads as administrative trivia. It is usually the highest-impact finding on a small business
site: trivially exploitable, needs no access to any system, and targets clients and
candidates rather than infrastructure. Invoice fraud and fake job-offer scams both start
here. Rate it High and explain the business mechanism.

**Over-rating version overlap.** A dependency inside a published CVE range, where the
vulnerable code path is absent from the deployment, is **Info**, not High. Report it — with
the gating reasoning, the fact that scanners will flag it, and the note that the protection
is architectural rather than version-based. Do not inflate it to make the report look
weightier; that is how reports get dismissed.

## Tone

Direct, specific, non-alarmist. No "critical vulnerability discovered!!!" and no "the site
appears to potentially have some issues."

- **Do** distinguish confirmed from inferred. "No DKIM record was found on any of 38 common
  selectors — this is an inference from a bounded sweep; verify in your provider's console."
- **Do** say when a result is inconclusive and why. A `signature-only` sink analysis on a
  single-bundle build is unverified, not clean.
- **Don't** hedge everything into meaninglessness. If HSTS is absent, say it is absent and
  what that permits.
- **Don't** pad. Twelve real findings beat forty with noise.

## Structure that gets read

Put the architecture sentence first. "This is a static client-side SPA with no backend, so
SQL injection, RCE and auth bypass are architecturally impossible; risk concentrates in
email spoofing, third-party form abuse and browser-level hardening." That one sentence
recalibrates every finding that follows and is usually the most useful thing in the report.

Then: executive summary → findings table → details → what is done well → prioritised roadmap
→ verification checklist → appendices.

The **roadmap** is what the owner actually uses. Group by time horizon, give each item an
effort estimate, and order by impact-per-minute. Call out fixes that resolve multiple
findings at once — "one `.htaccess` rewrite fixes F-05, F-09 and F-10 together" is far more
motivating than three separate items.

The **verification checklist** closes the loop: exact commands so the owner can confirm each
fix independently rather than trusting you.

## The false-positive appendix

Always include one. It is the strongest credibility signal available, because it shows what
you checked and rejected rather than only what you reported.

Format:

| Pattern matched | Verdict | Reason |
|---|---|---|
| `http://localhost` in bundle | False positive | Default inside react-router's `createURL` helper, not app config |
| `dangerouslySetInnerHTML` (12×) | False positive | All inside minified react-dom property handling |
| `javascript:` URI (2×) | False positive | React's own `javascript:` URL blocker — a defence, not a sink |
| `doubleclick` (3×) | False positive | React's `onDoubleClick` synthetic event names |
| `clarity` (6×) | False positive | Marketing copy, not the Microsoft Clarity tracker |
| Bootstrap XSS CVEs | Not exploitable | CSS only; no Bootstrap JS and no jQuery, so no execution path |
| CVE-2026-53667 | Not exploitable | Requires RSC APIs; `RSCErrorHandler` absent from bundle |

Note the distinction between **false positive** (the match does not mean what the pattern
implies) and **not exploitable** (the weakness is real in the version, but the code path is
absent from this deployment). Conflating them is a common error, and a reviewer who spots it
will discount the rest.

## Remediation quality

Generic advice is worse than none, because it consumes the reader's attention without
reducing risk.

| Bad | Good |
|---|---|
| "Improve your security headers" | The exact `Header always set` block, plus the note that `always` is required for headers to be emitted on 4xx/5xx |
| "Enable DMARC" | The three-phase sequence monitor → quarantine → reject, with the records for each, and a warning not to skip ahead |
| "Set SPF to -all" | "Once DKIM is live **and** every sender is enumerated. Switching early drops legitimate mail." |
| "Enable HSTS" | Deploy at `max-age=300` first; `includeSubDomains` forces **every** subdomain to HTTPS-only, so verify `ftp.`/`mail.`/`autodiscover.` first; preload removal is slow |
| "Update dependencies" | Exact target versions, the rebuild step (the served bundle must actually change), and CI gating so it cannot regress |

Always include the ordering constraints and the failure modes. The advice that gets people
into trouble is the correct action performed in the wrong order.

## Before you deliver

- Does every finding have verbatim, reproducible evidence?
- Is every CVE claim accompanied by an exploitability judgement, not just version overlap?
- Are public-by-design keys distinguished from real credential leaks?
- Is the limitations section present, and does it say that absence of a finding is not
  evidence of security?
- Are correct controls acknowledged?
- Does the roadmap have effort estimates and call out multi-finding fixes?
- Is there a verification checklist the owner can run themselves?
- Is the false-positive appendix there?
- If the user does not own the target, is disclosure guidance included and is the framing
  clearly "report" rather than "pentest"?
