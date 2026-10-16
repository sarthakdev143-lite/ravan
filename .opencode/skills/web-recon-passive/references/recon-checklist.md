# Passive recon checklist — zero-target-traffic sources first

All items below are public-record or third-party queries; no target load.

## Certificate transparency (keyless)

- `https://crt.sh/?q=%.example.com&output=json` — subdomains that ever
  held certs. Blind spots: wildcards, non-HTTPS names. Polite spacing.
- Record issuer, expiry, SAN coverage alongside findings.

## Registration context

- WHOIS/RDAP: registrant org, nameservers, dates, registrar. Standard
  passive OSINT — collect before asserting ownership narratives.

## Email posture (graded, not presence-checked)

- SPF (lookup-count ≤10), DKIM selectors + key size, DMARC policy +
  enforcement + `rua`, MTA-STS DNS + policy-file fetch
  (`https://mta-sts.<domain>/.well-known/mta-sts.txt`: mode/mx/max_age),
  TLS-RPT `rua`, DANE TLSA, BIMI (informational), MX redundancy/PTR,
  STARTTLS. MTA-STS: testing + RPT monitoring ≥2 weeks before enforce.

## DNSSEC / TLS depth

- DNSSEC: chain-of-trust validation (presence alone is not validation;
  verify with dnsviz and record the method).
- TLS: cipher-suite posture, HSTS-preload-list membership, CT/SCT check on
  served cert, OCSP/CRL revocation signal — beyond handshake + legacy probes.

## Headers / routing / client bundle

- Numeric posture score (Observatory-style) for trending, not just flags.
- Per-resource SRI coverage (not boolean), inline `sourceMappingURL`
  data-URI inspection, error-page vs primary policy diff, per-path header
  consistency beyond the SECURITY_HEADERS set.
- CMS signals (readme/meta-generator) noted with under-reporting caveat.

## Rules

Respect request budget + delay. Third-party queries (CT, RDAP, feeds) need
no target authorization but DO need the engagement's authorization context
recorded. Every enrichment carries method + confidence.
