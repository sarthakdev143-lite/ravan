# web-recon-passive

An [OpenCode](https://opencode.ai) skill for **passive** external security review of a web
target. Pure Python standard library — no pip installs, no browser, no scanner.

Built from a real assessment. Every false-positive filter in here exists because the tool
produced that exact false positive during development and had to be corrected.

## Install

Copy the folder into any location OpenCode scans for skills:

```bash
# global (available in every project)
cp -r web-recon-passive ~/.config/opencode/skills/

# or project-local
cp -r web-recon-passive .opencode/skills/
```

Also discovered at `.claude/skills/`, `~/.claude/skills/`, `.agents/skills/` and
`~/.agents/skills/` — the format is Claude-compatible, so the same folder works in Claude
Code without modification.

The directory name **must** stay `web-recon-passive`: OpenCode requires `name` in the
frontmatter to match the containing directory.

Verify it loaded:

```bash
ls ~/.config/opencode/skills/web-recon-passive/SKILL.md
```

Then in OpenCode, either invoke `/web-recon-passive` or just ask naturally — the skill is
auto-selectable from its `description`:

```
> do a passive security review of example.com
> what's the email spoofing risk on mydomain.com?
> check the security headers and TLS on our site
```

## Use the scripts directly (no agent needed)

```bash
cd scripts
python3 recon.py --target https://example.com \
                 --i-am-authorized \
                 --contact you@example.com \
                 --out ./report
```

`--i-am-authorized` is mandatory; without it the tool prints the scope warning and exits
`2`. Set `--contact` to something real — it goes in the User-Agent so operators can identify
you.

Requires Python 3.8+. Test offline:

```bash
python3 test_checks.py                             # 42 unit tests, no network
python3 validate_against_captured_bundle.py <js>   # replay against a real bundle
```

## What it checks

| Area | Coverage |
|---|---|
| DNS / email | SPF qualifier analysis, DMARC policy + enforcement, DKIM sweep across 38 selectors, null-MX (RFC 7505) handling, CAA, DNSSEC, MTA-STS, TLS-RPT, wildcard detection, notable subdomains |
| TLS | Certificate chain, validity, expiry countdown, SAN coverage, TLS 1.0/1.1 rejection, self-signed detection |
| HTTP headers | Full security-header scorecard, CSP *quality* analysis (not just presence), HSTS max-age/preload eligibility, cookie flags, disclosure headers, cross-path consistency |
| Attack surface | HTTP method allowance, TRACE, SPA deep-link routing, standards files, source-map exposure, HTTP→HTTPS redirect, www canonicalisation |
| Client bundle | Secret patterns across 20+ providers, public-by-design endpoint labelling, DOM-XSS sinks, version fingerprinting with confidence, RSC/server-runtime markers, sanitiser-vs-renderer mismatch, SRI, debug leftovers, internal URLs |
| Error pages | Platform-injected analytics/tracking, end-of-life libraries, missing CSP |
| Dependencies | GitHub Advisory Database + NVD correlation, with exploitability gating |

Outputs JSON (all facts, per-file attribution, full request log) and a Markdown report.

## What it deliberately cannot do

There is no port scanning, directory brute-forcing, fuzzing, injection testing,
authentication attack, exploitation or form-submission code in this project. It is not
disabled by a flag — it does not exist. A request budget and inter-request delay are
enforced so it cannot generate meaningful load.

This is reconnaissance that tells you where to point real tooling, not a replacement for it.
Active testing requires written authorisation and a purpose-built tool (nuclei, nikto, ZAP,
Burp). See `references/legal-and-scope.md`.

## The design problem this solves

Naive pattern matching on a minified production bundle reports framework internals as
application vulnerabilities. During development this tool flagged:

| False positive | Reality |
|---|---|
| `dangerouslySetInnerHTML` ×12, `innerHTML` ×5 | minified react-dom property handling |
| `http://localhost` | react-router's `createURL` fallback base URL |
| `javascript:` URI ×2 | **React's own `javascript:` URL blocker** — a defence, not a sink |
| `console.log` ×12 | React internals; exactly 1 was real application logging |
| `doubleclick` ×3 | React's `onDoubleClick` synthetic event names |
| `clarity` ×6 | marketing copy, not the Microsoft Clarity tracker |
| Algolia `apiKey` | a **search-only** key, public by design — not a credential leak |
| `admin./dev./phpmyadmin.` subdomains | wildcard DNS made every name resolve |
| 13 "resolving" subdomains | SOA records from the **authority** section of negative answers being mistaken for answers |
| `TRACE enabled` | HTTP 405 means the method is *refused* |
| Bootstrap 3.3.7 XSS CVEs | CSS only, no JS, no jQuery — no execution path |
| MTA-STS missing | the domain publishes a null MX and accepts no mail |

Three filtering mechanisms handle this:

1. **Filename classification** — vendor chunks (`framework-*.js`, `main-*.js`,
   `polyfills-*.js`, `react-dom*.js`) are separated from application chunks. Reliable and
   bundler-agnostic.
2. **Signature filtering** — for single-bundle builds (Vite concatenates vendor and app
   code) where filenames cannot help. Covers both esbuild and webpack/terser output styles.
3. **Explicit honesty** — when only stage 2 was available, findings record
   `method: signature-only` and an inconclusive-result finding is emitted, so a negative is
   never presented as verified.

Every case above is pinned by a test. If you add a pattern to `checks.py`, add a fixture to
`test_checks.py` proving it does not fire on react-dom.

## Layout

```
web-recon-passive/
├── SKILL.md                                  agent-facing instructions + judgement layer
├── README.md                                 this file
├── scripts/
│   ├── recon.py                              CLI orchestrator (authorization gate lives here)
│   ├── checks.py                             all detection logic + finding construction
│   ├── dnslib.py                             stdlib-only DNS resolver, SPF/DMARC parsers
│   ├── webfetch.py                           rate-limited polite HTTP client
│   ├── cve.py                                GHSA + NVD correlation, exploitability gating
│   ├── test_checks.py                        42 offline unit tests
│   └── validate_against_captured_bundle.py   16 offline checks against a real bundle
└── references/
    ├── legal-and-scope.md                    authorization, jurisdiction, disclosure etiquette
    ├── reporting-guide.md                    severity calibration, tone, report structure
    └── remediation-library.md                tested .htaccess / nginx / DNS / build fixes
```

`SKILL.md` holds the workflow and the judgement rules; `references/` holds depth that the
agent reads on demand. That split matters — OpenCode loads only the frontmatter
`description` into the model's context until the skill is invoked, so keeping `SKILL.md`
focused keeps token cost down.

## Extending

- **New detection** — add to `checks.py`, return `checks.F(...)` findings, add a fixture to
  `test_checks.py`.
- **New secret pattern** — add to `SECRET_PATTERNS`. If the key is public by design, add the
  label to `PUBLIC_BY_DESIGN` so it is reported as an abusable endpoint rather than a leak.
- **New framework internals signature** — add to `LIBRARY_NOISE`, and note which minifier
  emits that form.
- **New vendor chunk name** — extend `VENDOR_CHUNK_RE`.

Keep findings as declarative data, not prose. The calling agent re-ranks them, cross-checks
exploitability and writes its own report; hardcoded narrative prevents that.

## License

MIT.
