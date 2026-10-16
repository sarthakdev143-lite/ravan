# Detect & respond — log schema, alert rules, IR runbooks

## Log schema (structured JSON, UTC, request-ID traced)

Log: auth success/failure, password resets, MFA changes, privilege grants,
admin actions, WAF blocks, CSP-violation reports, cert-renewal failures,
secret-access events. Never log passwords, tokens, or full PII (redact).
Forward append-only to SIEM; retain per policy; keep clocks synced (NTP).

## Alert rules (threshold + query, tune per target)

1. Credential-stuffing spike: >20 failed logins / user / 5 min.
2. Mass 401→200 transition on one account (spray success signal).
3. Impossible travel (geo jump vs session lifetime).
4. Privilege grant outside change window.
5. WAF probe burst: SQLi/XSS strings >50 / IP / min.
6. New-origin CORS/CSP violation burst (active probing).
7. Secret committed to main (push-protection bypass attempt).
8. Dependency KEV hit on deployed version.
9. Certificate expiry <14d; DMARC forensic (`ruf`) failure spike.
10. SSRF egress anomaly (internal-IP outbound attempts).

## IR runbooks (per class: takeover, defacement, RCE, supply-chain, mail abuse)

1. **Identify/preserve:** freeze logs, snapshot, chain of custody, order of
   volatility (memory → disk → logs).
2. **Contain:** isolate host, revoke sessions/tokens, rotate secrets,
   block IOCs at edge.
3. **Eradicate/recover:** patch from known-good, rebuild (not repair)
   compromised images, restore from tested backups (RPO/RTO tracked).
4. **Notify:** severity-gated comms; breach-notification timelines apply
   (GDPR 72h); legal looped before public statements.
5. **Learn:** tabletop follow-up, detection gap → new rule above.

## Readiness

Canary tokens + honeypot creds deployed; backups encrypted offsite with
restore drills; ATT&CK-mapped detections (T1078, T1190, T1133, T1505,
T1071, T1048) reviewed quarterly.
