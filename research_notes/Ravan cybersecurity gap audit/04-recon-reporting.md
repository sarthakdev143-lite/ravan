# Ravan Recon & Reporting Quality Gap Audit

## 1. What recon is missing

### Takeaway
Ravan's passive recon is broad on DNS/TLS/headers/bundle analysis but has no certificate-transparency subdomain enumeration, no WHOIS/RDAP, no BIMI, shallow MTA-STS/TLS-RPT validation, presence-only DNSSEC checks, and coarse CSP/SRI scoring — each a concrete, fixable coverage gap versus industry passive tradecraft.

### Cited Findings
- Certificate-transparency logs record every publicly issued TLS certificate including SANs/CNs, and querying `https://crt.sh/?q=%.example.com&output=json` yields subdomains without touching the target; results are historical and passive, and wildcard certs / non-HTTPS subdomains are known blind spots — [CyberSec Lounge crt.sh guide](https://www.cybersec-lounge.com/passive-recon-crt-sh); [HackIndex CT enumeration](https://hackindex.io/services/web/reconnaissance/certificate-transparency-enumeration)
- Subfinder's default `crtsh` source queries CT logs with no API key via PostgreSQL + HTTP fallback, and is enabled by default — [DeepWiki subfinder CT sources](https://deepwiki.com/projectdiscovery/subfinder/3.3.2-certificate-transparency-sources)
- Ravan's subdomain enumeration is a fixed 12-name wordlist (`ftp, sftp, cpanel, webmail, admin, dev, staging, test, beta, old, backup, phpmyadmin, mail`) with DNS resolution checks and no CT, passive-DNS, or search-engine source (`checks.py:390-401`).
- WHOIS/RDAP (registrant org, nameservers, registration dates, registrar) is standard passive OSINT tradecraft — [ReconShield passive OSINT guide](https://reconshield.in/blog/anatomy-of-passive-osint); [TryHackMe Passive Recon](https://tryhackme.com/room/passiverecon) — but ravan collects no WHOIS/RDAP facts at all (`checks.py:check_dns` covers A/AAAA/NS/MX/TXT/CAA/DNSSEC only).
- Full email-security grading checks SPF, DKIM, DMARC, MTA-STS policy file (mode/mx/max_age), TLS-RPT, DANE, BIMI, rDNS, STARTTLS and blocklists with an A–F score — [mailgrade](https://github.com/aloki-alok/mailgrade); weighted model Email Auth 50% / MTA-STS 20% / Infra 20% / TLS-RPT 10%, BIMI informational-only — [SwissArmyTechTools analyzer](https://swissarmytechtools.com/email-security-analyzer/)
- Ravan checks MTA-STS/TLS-RPT DNS TXT presence only and never fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt`, never validates mode/mx/max_age, never checks BIMI (`default._bimi`), DANE TLSA, SPF lookup-count (10-limit), DKIM key size, MX redundancy/PTR, or STARTTLS (`checks.py:362-380`).
- Correct MTA-STS rollout is testing mode + TLS-RPT monitoring for 2+ weeks before enforce, with FQDN (never wildcard) MX patterns — [UK Gov MTA-STS/TLS-RPT setup](https://www.security.gov.uk/policy-and-guidance/set-up-tls-rpt-and-mta-sts/)
- A reference MTA-STS assessor grades `mode=testing/none` as low, MX-mismatch as medium, short max_age as info — [gecko MTA-STS assessor commit](https://github.com/danielmichaels/gecko/commit/38cd6d7ac3f55662df8b4ca214bddb7566611a0b)
- Ravan's DNSSEC check is presence-only (DNSKEY answers OR DS record, `checks.py:347-349`) with no chain-of-trust validation; operational guidance is to verify with dnsviz — which the tool cites but cannot perform itself (`checks.py:359-360`).
- Mozilla Observatory scores from a 100 baseline with penalties then bonuses (bonuses only if ≥90/A), grades A+ (100+) down to F (0–24), max 145 — [MDN Observatory scoring](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring); it individually tests CSP, HSTS, redirection, cookies — [MDN Observatory](https://developer.mozilla.org/en-US/observatory)
- Ravan's CSP analysis flags `unsafe-inline`/`unsafe-eval`/`*` tokens but has no numeric quality score/grade, no `report-uri` enforcement weight, and SRI is a boolean (`integrity=` present/absent in HTML) with no per-resource coverage accounting (`checks.py:620-646, 1357-1373`).
- Header-consistency checking only compares extra `--path` flags against `/` and only for SECURITY_HEADERS set membership (`checks.py:868-888`); error-page headers are inspected separately but never diffed against the primary policy, and `Referrer-Policy`/`Permissions-Policy` granularity is presence-only.
- Source-map detection fetches only `<asset>.js.map` candidates for the first 14 assets and never inspects inline `//# sourceMappingURL=` data-URI content or validates map contents (`checks.py:992-1014`); function ends with dangling comment "inline sourceMappingURL comments" (`checks.py:1013`).
- TLS assessment negotiates only the default handshake plus TLS 1.0/1.1 probes; there is no cipher-suite enumeration, no HSTS-preload-list membership check, no CT-log / SCT verification of the served cert, and no OCSP/CRL revocation signal (`checks.py:478-613`).

### Inferences
- The highest-ROI recon additions are all zero-target-traffic third-party queries: crt.sh CT enumeration, RDAP/WHOIS, and MTA-STS policy-file fetch — none require new authorization posture.
- Email-security depth is the weakest pillar relative to its business impact: ravan correctly rates DMARC/SPF high but cannot distinguish `mode=testing` from `mode=enforce` MTA-STS or validate TLS-RPT `rua=`, so a domain with toothless transport security looks identical to a hardened one.
- Absence of a numeric posture score (Observatory-style) makes regression tracking and board-level trending impossible; current output is findings-list only.

### Gaps
- No reliable source found quantifying CT-log coverage lag (how quickly new certs appear) for 2026; noted as unknown rather than asserted.
- Whether BIMI absence should score at all is unresolved: sources treat it as informational/optional — [SwissArmyTechTools](https://swissarmytechtools.com/email-security-analyzer/) — so recommending a BIMI finding risks noise; needs a deliberate severity policy, not assumed.

## 2. Where false-positive discipline fails

### Takeaway
Ravan's false-positive apparatus (vendor-chunk classification, LIBRARY_NOISE signatures, public-by-design labels, wildcard suppression, 405/501 handling, SOA traps, gated-CVE verdicts) is unusually strong for its class — but every mechanism has a documented residual weakness the reports must carry as explicit uncertainty rather than silent confidence.

### Cited Findings
- Ravan establishes architecture before severity (static SPA ⇒ SQLi/RCE/SSRF/auth-bypass architecturally impossible), distinguishes version overlap from exploitability (`exploitable` vs `gated` verdicts kept in-report), and recalibrates severity to the target — `ravan.md:227-260`; `SKILL.md:88-154`.
- Vendor-chunk filename classification is the primary sink/secret filter with LIBRARY_NOISE signatures as single-bundle fallback, and the method is recorded per-result so reviewers can judge trust — `checks.py:64-74, 1059-1102`.
- The LIBRARY_NOISE list itself warns it is minifier-specific (Vite/esbuild vs Next.js/webpack emit different output) and that signature lists tuned on one bundler leak false positives on the other — `checks.py:31-37`.
- Public-by-design keys (Web3Forms, Formcarry, Formspree, Algolia search-only) are reported as abusable endpoints, never critical leaks — `checks.py:109-114, 1207-1229`; Stripe publishable keys have a pattern but are NOT in PUBLIC_BY_DESIGN, and Firebase web config requires sibling-key confirmation — `checks.py:81, 96, 113-114`.
- Wildcard DNS detection suppresses all subdomain findings with an info-level explanation — `checks.py:382-386, 404-424`.
- 405/501 (plus 403/400) are treated as method-refused, with only 2xx flagged; TRACE at 200 is the sole method finding — `checks.py:908-928`.
- SOA-in-authority-section and NSEC-denial traps are explicitly handled via `resolves_to_address` existence checks — `checks.py:393-398`; `ravan.md:256-257`.
- Gated CVEs must be kept in-report (scanners will flag them; protection is architectural not version-based), never reported as live and never omitted — `SKILL.md:103-118`; reporting-guide distinguishes false-positive (match means something else) from not-exploitable (real weakness, absent code path) — `reporting-guide.md:90-93`.
- React's own `javascript:` URL blocker and form-action guard are inventoried as defences that must not be reported as sinks — `checks.py:59-62`; `reporting-guide.md:80-88` tabulates the canonical FP appendix rows (localhost-in-createURL, dangerouslySetInnerHTML-in-react-dom, doubleclick, clarity-copy).
- DNSEC/NSEC denial vs zone-dump and DMARC `p=none`-as-starting-point vs protection distinctions are enforced in prose — `ravan.md:256-257`; `checks.py:258-260`.

### Inferences
- Residual risk concentrates in four named places the tool already flags honestly: (1) single-bundle builds where filename classification is unavailable (`signature-only` verdicts); (2) medium/low-confidence version fingerprints feeding CVE correlation; (3) bounded DKIM selector sweeps presented as inference, not proof; (4) local-OpenSSL legacy-TLS limitations recorded as `TLS-LEGACY-INCONCLUSIVE` rather than clean.
- Stripe publishable-key handling is the one classification inconsistency: `pk_live/pk_test` matches as a secret pattern without public-by-design labelling, inviting critical-leak over-rating of a publishable key — the exact error class the skill warns against.
- The CSP `unsafe-inline`-in-`style-src` carve-out (Tailwind/CSS-in-JS) is noted in remediation prose (`checks.py:750-751`) but `analyse_csp` flags `unsafe-inline` in `script-src`/`default-src`/`object-src`/`base-uri` without distinguishing style-src — a minor scoring-clarity gap.

### Gaps
- No measurement found of LIBRARY_NOISE precision/recall against webpack/Turbopack 2026-era bundles; the tool's own comment concedes bundler drift — needs a `validate_against_captured_bundle.py` replay per release, which exists as a script but has no freshness evidence in-repo.
- CMS targets (WordPress/Drupal) are acknowledged as under-reported by the skill (`SKILL.md:100-101`) with no plugin/theme enumeration path even via passive readme/meta-generator signals — accepted limitation, but unquantified.

## 3. What evidence standards are absent

### Takeaway
Ravan mandates verbatim reproducible evidence per finding and ships machine-readable JSON + request logs — a solid base — but has no CVSS 4.0 scoring, no EPSS/KEV prioritization signal, no confidence levels on findings, and no reachability/taint analysis beyond presence, leaving severity as analyst judgement without a threat-intel anchor.

### Cited Findings
- EPSS is a daily-published ML model estimating probability a CVE is exploited in the wild in the next 30 days, with 0–1 probability plus percentile, free via CSV/API — [FIRST EPSS](https://www.first.org/epss/); FIRST publishes explicit guidance on combining EPSS with CVSS and KEV, setting thresholds, and avoiding misuses — [FIRST EPSS](https://www.first.org/epss/)
- CVSS v4.0 with supplemental metrics is the current FIRST standard, with calculator, spec, user and implementation guides — [FIRST EPSS page linking CVSS-SIG](https://www.first.org/epss/); industry practice increasingly chains CVSS + EPSS + KEV as a decision tree for patch prioritization (2025 framework literature) — search result [arXiv 2506.01220](https://arxiv.org/html/2506.01220v3); EPSS v4 (Mar 2025) scores backlog CVEs lacking CVSS — [DecryptionDigest EPSS guide](https://www.decryptiondigest.com/blog/epss-vulnerability-prioritization-patching-workflow-guide)
- Non-federal orgs increasingly use CISA KEV as a prioritization input and CVSS 4.0 adds supplemental metrics — [DefenderMate comparison](https://www.defendermate.com/dmate-blog/cvss-vs-epss-vs-ssvc-vs-kev)
- Ravan findings carry `severity + status + exploitable` but no CVSS vector/score, no EPSS percentile, no KEV-membership check, and no confidence field; the `F()` constructor has no slots for them (`checks.py:159-165`).
- Ravan's severity scale is defined qualitatively (critical = exploitable now → compromise; high = exploitable now with business impact; etc. — `checks.py:6-11`) and the reporting guide gives severity tests ("Can an attacker own the system today?") — `reporting-guide.md:15-27` — but nothing binds tool severity to CVSS/EPSS/KEV, so two analysts can score identically-evidenced findings differently with no tiebreak rule.
- Reachability analysis exists only for JS sinks (in-app-code vs vendor-filtered counts with samples) and Bootstrap-JS-vs-CSS-only gating (`checks.py:1283-1324, 1512-1527`); CVE findings from advisory correlation have `gated` verdicts via RSC/server-runtime markers (`SKILL.md:103-116`) but no EPSS/KEV overlay to order the gated-vs-live queue.
- Every finding requires verbatim evidence from the JSON `evidence` array; a finding without evidence is an opinion; evidence must be copy-pasteable with observation date — `reporting-guide.md:5-13`; outputs include full request logs — `SKILL.md:72-73`.
- Limitations-section discipline is mandatory (passive ≠ pentest; absence of finding ≠ security; list untested areas) — `ravan.md:271-272`; `SKILL.md:162-176`; `reporting-guide.md:111-123` pre-delivery checklist.
- Confidence signalling is partial: version confidence (`high/medium/low`) and `signature-only` sink caveats exist as facts, but findings themselves carry no `confidence: confirmed/inferred/inconclusive` label, forcing readers to mine `facts.*` to learn a verdict is shaky.

### Inferences
- Adding three fields per finding — `cvss` (vector+score where applicable), `epss_percentile` + `kev: true/false`, and `confidence: high/medium/low` with reason — would close most of the board-readiness gap without changing any detection logic.
- Advisory correlation via GitHub Advisory DB + NVD (`SKILL.md:36-39`) without EPSS/KEV means dependency findings are ordered by severity-class alone; a medium-severity KEV-listed item will currently rank below a high-severity never-exploited item — the exact inversion EPSS+KEV chaining exists to prevent.
- The JSON-facts + Markdown-report + request-log pipeline already satisfies reproducibility; the missing piece is *prioritization defensibility*, not evidence capture.

### Gaps
- Could not verify from local files whether advisory correlation emits CVSS scores at all (recon.py / advisory module not in the assigned read set); flagged as needing confirmation before specifying the CVSS-field fix.
- No 2026 source found establishing an EPSS-percentile threshold consensus (e.g., ≥0.88 vs ≥0.95) for small-business passive reports; any threshold ravan adopts must be stated as policy choice, not standard.

## 4. How best reports structure

### Takeaway
Ravan's prescribed report shape already matches OWASP/PTES best practice (scope/methodology/limitations → exec summary → findings table → details → done-well → roadmap → verification → appendices) and adds two differentiators — architecture-first framing and a false-positive appendix — but lacks attack-chain narrative, retest workflow, and disclosure-etiquette operational detail.

### Cited Findings
- OWASP WSTG mandates reports appeal to both executives and technicians: objective, business-context key findings, strategic non-technical recommendations in the summary; full technical detail per finding for engineers — [OWASP WSTG Reporting](https://wstg.owasp.org/latest/5-Reporting/01-Reporting_Structure/)
- PTES requires executive summary (background, posture narrative, risk ranking with scoring mechanism, general findings with graphics, recommendation summary, strategic roadmap in time/objective increments) plus technical details with proof, post-exploitation business linkage, and risk quantification in client terms — [PTES Reporting](https://pentest-standard.readthedocs.io/en/latest/reporting.html)
- The executive summary is the only section decision-makers read: 1–2 pages max, five questions (what tested, headline, business impact, top-3 actions, cost), no jargon/CVSS/CVE in that section; separate sections per audience (board / CISO / IT) — [Hedgehog good-report guide](https://www.hedgehogsecurity.co.uk/blog/what-a-good-penetration-test-report-looks-like); echoed by HackTheBox (BLUF, vendor-agnostic recommendations) — [HTB report guide](https://www.hackthebox.com/blog/penetration-testing-reports-template-and-guide)
- Best reports include an attack narrative chaining findings (what enabled what, cheapest break-point) — its absence is called the most-missed highest-value section — [Hedgehog](https://www.hedgehogsecurity.co.uk/blog/what-a-good-penetration-test-report-looks-like); remediation steps must be implementation-ready (GPO paths, exact commands, verification per finding), grouped immediate/short/medium-term with dependencies and effort — [Hedgehog](https://www.hedgehogsecurity.co.uk/blog/what-a-good-penetration-test-report-looks-like); [CyCognito guide](https://www.cycognito.com/learn/penetration-testing/penetration-testing-report/)
- Ravan's shape — scope/methodology/limitations → exec summary (architecture, risk, counts, stack) → findings table → details → done-well → roadmap (now/next/later + effort) → verification checklist → appendices (advisories, logs, rejected positives) — `ravan.md:281-284`; `SKILL.md:162-181`; architecture-first sentence is prescribed as the report's most useful line — `reporting-guide.md:55-60`.
- Ravan's roadmap must group by horizon with effort estimates and call out multi-finding fixes; verification checklist gives exact owner-runnable commands; remediation table contrasts generic vs exact-directive advice with ordering/failure-mode warnings — `reporting-guide.md:65-109`.
- Disclosure: third-party targets get responsible-disclosure framing (not pentest), contact route, 90-day window, no exploitation suggestions — `SKILL.md:19-33`; `reporting-guide.md:122-123`.
- The 90-day norm traces to Google Project Zero's 90-day deadline (90+30 variant) — [Project Zero policy](https://projectzero.google/vulnerability-disclosure-policy.html); [Wikipedia CVD](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure); ZDI uses 60 days for some categories, 90 for others — [ZDI policy](https://www.zerodayinitiative.com/advisories/disclosure_policy/); US federal VDPs (Commerce, HHS) require 90-day confidentiality — [DOC VDP](https://www.commerce.gov/vulnerability-disclosure-policy), [HHS VDP](https://www.hhs.gov/vulnerability-disclosure-policy/index.html)
- In 2026 the 90-day window is contested: AI-assisted patch-weaponization arguments claim it is too slow — [Tom's Hardware](https://www.tomshardware.com/tech-industry/cyber-security/standard-90-day-vulnerability-disclosure-policy-is-likely-dead-thanks-to-ai-leaving-worlds-systems-exposed-to-zero-day-attacks-security-expert-details-how-llm-assisted-bug-hunting-ushers-in-a-new-cyberworld-orders) — but no replacement norm has displaced it in cited policies.

### Inferences
- Ravan meets ~80% of best-practice structure; the three structural additions with highest value are: (1) attack-chain narrative adapted to passive work (how email-spoofing + form-abuse + missing-framing chain into one business compromise story); (2) a retest workflow (what to re-run, when, pass criteria per finding — currently only a verification checklist exists, which confirms fixes but schedules nothing); (3) disclosure operational detail (severity-gated timelines, safe-harbor language, contact-template, what to do if no security.txt exists — currently a single 90-day mention).
- The false-positive appendix and done-well section are genuine differentiators versus commodity scanner reports; the audit's recommendation is to keep and strengthen them (standardized FP table format already exists — `reporting-guide.md:80-88`), not to trade them for more findings volume.
- Executive-summary discipline ("no CVSS/CVE/jargon, 1–2 pages, top-3 actions") should be explicitly imported: ravan's current exec-summary spec (architecture, risk, counts, stack) risks reading as technical preamble rather than a funding decision document.

### Gaps
- No source found prescribing retest SLA windows specifically for passive-recon findings (vs pentest retests); recommended windows would be policy invention — flagged, not asserted.
- Board-level cost/quantification guidance (breach-cost, FAIR-style monetization per PTES risk-quantification section) has no small-business-appropriate formulation in the sources reviewed; ravan currently omits cost entirely — needs targeted follow-up research, not a guess.
