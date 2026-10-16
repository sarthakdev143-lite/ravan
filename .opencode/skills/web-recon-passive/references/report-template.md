# Report template — blocking checklist (all sections required)

A report missing any section is rejected. Fill every section; never ship
prose-only.

1. **Scope, methodology & limitations** — what was done, what was
   deliberately NOT done, coverage matrix (covered/partial/absent per
   vuln class), and that absence of a finding is not evidence of security.
2. **Executive summary (1–2 pages)** — architecture in one paragraph,
   overall risk, severity counts, detected stack, TOP-3 actions with cost.
   No jargon, no CVE soup — a funding document.
3. **Attack-chain narrative** — how findings combine into one compromise
   story (e.g. spoofed mail → credential harvest → form abuse); cheapest
   break-point first.
4. **Findings table** — ID, title, severity, status, KEV/EPSS/confidence.
5. **Detailed findings** — per finding: evidence (verbatim), mechanism,
   target-terms impact, exact fix + failure modes + rollback, verification
   command, ATT&CK IDs where applicable.
6. **What is done well** — correct controls listed (calibrates the reader).
7. **Prioritized roadmap** — now / next / later + effort estimates, KEV +
   exposed first.
8. **Verification checklist** — owner-runnable commands per fix.
9. **Retest workflow** — what to re-run, when, pass criteria per finding ID.
10. **Disclosure ops** — contact route, severity-gated timelines (90-day
    default norm), safe-harbor note, no-security.txt fallback.
11. **Run manifest** — agent file hash, skill version, date, model note
    (model-dependent), request-log reference.
12. **Appendices** — advisory detail, full request log, rejected positives
    WITH reasons (strongest credibility signal).

Tone: direct, specific, non-alarmist. Tables over prose. Every finding
needs verbatim evidence — a finding without evidence is an opinion.
Outputs are machine-assisted drafts requiring qualified-tester attestation
for compliance use.
