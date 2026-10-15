---
name: web-recon-passive
description: Passive external security review of a website using only publicly observable information — DNS/email authentication (SPF, DKIM, DMARC, CAA, DNSSEC, MTA-STS), TLS configuration, HTTP security headers, attack-surface mapping, and static analysis of publicly served JS bundles for hardcoded secrets, third-party endpoints and DOM-XSS sinks, with version-to-CVE correlation. Use when asked to assess, review, audit or produce a vulnerability report for a web domain or URL, or to check its security posture, headers, TLS or email spoofing risk. Passive only — contains no port scanning, brute-forcing, fuzzing, injection or exploitation capability, so it is safe to run on third-party targets for responsible-disclosure purposes. Requires an explicit authorization assertion.
license: MIT
compatibility: opencode
metadata:
  audience: "developers, security reviewers"
  workflow: "security-assessment, responsible-disclosure"
  opencode/slash: "true"
  opencode/autoinvoke: "true"
---

# Passive Web Security Review

Produce an evidence-based external security assessment of a single web target using
**only** what an anonymous visitor can observe. Pure Python standard library — no pip
installs, no browser, no scanner.

## Step 0 — Authorization gate (do not skip)

Before running anything, establish who the target belongs to.

- **If the user owns or operates the target** — proceed. Confirm they want a passive-only
  review, or whether they also intend to commission active testing separately.
- **If the user does NOT own it** — proceed, but frame the entire deliverable as a
  **responsible-disclosure report**, not a pentest. Add the disclosure guidance from
  `references/legal-and-scope.md`, name a contact route, and recommend a 90-day window.
  Never suggest exploitation, and never run the tool with intent to abuse a finding.
- **If ownership is ambiguous** — ask. Do not guess.

The script enforces this with a required `--i-am-authorized` flag and exits `2` without it.
That flag is the user's assertion, not a substitute for you establishing context.

## What this skill does and does not do

**Does:** DNS record review, TLS/certificate inspection, HTTP header analysis, routing and
method behaviour, standards-file checks, source-map exposure, static analysis of JS/CSS the
page itself references, secret and endpoint extraction, component version fingerprinting,
advisory correlation via the GitHub Advisory Database and NVD.

**Does not, and cannot:** scan ports, enumerate directories, fuzz, inject, brute-force,
authenticate, exploit, or submit forms. This code does not exist in the project — it is not
gated behind a flag. A request budget and inter-request delay are enforced so the tool
cannot generate meaningful load.

If the user asks for active testing, say plainly that this skill cannot do it, and that
active testing requires written authorization plus a purpose-built tool (nuclei, nikto,
ZAP, Burp). Offer to help draft a scope document instead.

## Running it

```bash
python3 scripts/recon.py \
  --target https://example.com \
  --i-am-authorized \
  --contact you@example.com \
  --out ./report
```

Useful flags:

| Flag | Purpose |
|---|---|
| `--contact EMAIL` | Goes into the User-Agent so operators can identify and reach you. **Always set this** — an anonymous UA on a third-party target is indistinguishable from an attack. |
| `--max-requests N` | Hard budget (default 400). Exceeding it aborts the run. |
| `--delay SECONDS` | Gap between requests (default 0.7). Raise it for small shared hosts. |
| `--dns-server IP` | Pin a resolver. Default tries 1.1.1.1, 9.9.9.9, 8.8.8.8. |
| `--no-cve` | Skip advisory correlation (offline / rate-limited runs). |
| `--path /foo` | Add paths to the header-consistency check. Repeatable. |
| `--json-only` | Emit JSON without Markdown. |

Outputs to `--out`: `<host>-<timestamp>.json` (machine-readable, all facts and request log)
and `<host>-<timestamp>.md` (human-readable report with full request log appended).

Exit codes: `0` ok · `2` authorization flag missing · `3` target unreachable.

## The part that matters: judgement, not detection

**A raw scan output is not a report.** The single most common failure in automated web
assessment is reporting a match without establishing whether it is reachable. Roughly half
of what naive pattern matching finds in a modern JS bundle is framework internals or
coincidental text.

The tool does mechanical filtering for you (vendor-chunk classification, framework-internals
signatures, public-by-design key labelling, wildcard-DNS detection). What it cannot do is
decide what the results *mean*. Before writing anything up, do this:

### 1. Establish the architecture first

Read `facts.dns`, `facts.tls`, `facts.headers`, `facts.bundle` from the JSON before touching
the findings list. The architecture determines which findings are real:

- **Static SPA, no backend** → there is no server-side attack surface. SQL injection, RCE,
  SSRF, auth bypass and file-upload-to-server are architecturally impossible. Do not imply
  otherwise. Risk concentrates in **email spoofing, third-party form abuse, client-side
  code and missing browser headers.** Say this explicitly — it is the most useful sentence
  in the report.
- **SSR / framework server** (`facts.bundle.spa_only == false`) → server-side findings
  become live. Re-read every "gated" CVE and reassess.
- **CMS (WordPress, Drupal, etc.)** → plugin/theme versioning and admin exposure dominate.
  This skill will under-report; say so.

### 2. Verify every CVE by exploitability, not version overlap

`facts.bundle.rsc_markers` and `server_runtime_markers` exist for this. A version inside a
published affected range is **not** automatically a vulnerability:

- Framework-mode DoS needs a server doing route matching.
- RSC/SSR CVEs need `react-server-dom-*` or an entry.server runtime.
- XSS in a specific component needs that component to be bundled and reachable.

The tool labels these `verdict: gated` with written reasoning. **Keep them in the report**
but state clearly that they are not exploitable as deployed, and explain why. Then add the
two caveats that make the finding still worth acting on: scanners will flag them regardless,
and the protection is architectural rather than version-based — enabling SSR later makes
them live with no code change that would alert anyone.

Never report a gated CVE as a live one. Never omit it either.

### 3. Interrogate the false positives yourself

The filtering is heuristic. Verify anything load-bearing:

- **Secrets** — is it a real credential, or a public-by-design key (Algolia search-only,
  Web3Forms/Formspree/Formcarry, Stripe *publishable*, Firebase *web* config)? These are
  different findings with different severities. Mislabelling a public search key as
  `CRITICAL credential leak` destroys the report's credibility.
- **Sinks** — check `facts.bundle.sinks[*].method`. If it says `signature-only`, vendor and
  app code share one bundle and the negative is unverified. Say so; recommend reviewing the
  unminified source.
- **Versions** — check `facts.bundle.version_confidence`. Only explicit runtime constants
  (`window.__reactRouterVersion`) are reliable. A generic `version:"x.y.z"` may belong to an
  unrelated library. If confidence is not `high`, tell the user to confirm against
  `package.json`/lockfile before acting.
- **Subdomains** — if `facts.dns.wildcard_dns` is true, every hostname resolves and
  subdomain findings are meaningless. The tool suppresses them; verify that it did.
- **`javascript:` URIs** — React itself ships a `javascript:` blocker. Confirm a match is
  not the framework's own defence before reporting it as an injection point.

### 4. Recalibrate severity to the actual target

The tool assigns a baseline severity. Adjust it to context and say why:

- Clickjacking on a static brochure page is low. On a page with a working form that submits
  real data, it is medium. On an authenticated settings page, high.
- Missing HSTS on a site with no login is lower impact than on one that handles credentials
  — but it still matters if forms capture personal data.
- Email authentication weaknesses are routinely the **highest-impact** finding on a small
  business site, because they are trivially exploitable, need no technical access, and
  target the company's clients and candidates rather than its infrastructure. Do not
  under-rate them just because they are "only DNS".

Severity must reflect impact on *this* target, not the generic CVSS of the weakness class.

### 5. Check what is done WELL

Report correct controls too: TLS 1.0/1.1 refused, `TRACE` disabled, no source maps
published, no cookies set, no hardcoded secrets, production build, `Allow` restricted. This
is not padding — it calibrates the reader on what the rest of the report means, and it stops
the assessment reading as a list of complaints.

## Report structure

Write Markdown. Recommended shape:

1. **Scope, methodology & limitations** — what was done, what was deliberately not done,
   and that absence of a finding is not evidence of security. This section is what makes
   the report defensible.
2. **Executive summary** — architecture, overall risk, severity counts, detected stack.
3. **Findings table** — ID, title, severity, status.
4. **Detailed findings** — evidence (verbatim, from the JSON), analysis, impact, remediation.
5. **What is done well.**
6. **Prioritised roadmap** — immediate / short term / medium term, each with effort estimate.
7. **Verification checklist** — commands the owner can run to confirm each fix.
8. **Appendices** — advisory correlation detail, full request log, false positives
   explicitly excluded with reasons.

Every finding needs **verbatim evidence** pulled from the JSON `evidence` array. A finding
without evidence is an opinion. Use `references/reporting-guide.md` for tone, phrasing and
the false-positive appendix format, and `references/remediation-library.md` for tested
copy-pasteable fixes (`.htaccess` header blocks, DNS records, SPA rewrite rules).

## Testing the tool itself

```bash
python3 scripts/test_checks.py                             # 42 offline unit tests
python3 scripts/validate_against_captured_bundle.py <js>   # replay against a real bundle
```

Both are offline and issue no requests. Run them after editing any pattern in `checks.py`.
Every test encodes a false positive this tool actually produced and then fixed — if you add
a pattern, add a fixture proving it does not fire on `react-dom`.

## Failure modes to avoid

- **Reporting version overlap as exploitation.** See §2. This is the most damaging error.
- **Rating a public-by-design client key as a critical leak.** See §3.
- **Letting minified framework internals become application findings.** See §3.
- **Subdomain findings under wildcard DNS.** See §3.
- **Omitting the limitations section,** which makes a passive review look like a pentest.
- **Generic remediation.** "Improve your security headers" is useless. Give the exact
  directive, the exact DNS record, and the exact rollout order — including the warnings
  (e.g. HSTS `includeSubDomains` breaks any subdomain lacking valid HTTPS).
- **Recommending `-all` SPF or `p=reject` DMARC as a first step.** Both drop legitimate
  mail. The sequence is monitor → quarantine → reject, and it must be stated.
