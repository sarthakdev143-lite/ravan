---
name: owasp-top-10
description: "Use when reviewing or hardening a web application against OWASP Top 10 risks — access control (IDOR), injection (SQL, command, XSS), cryptographic failures, insecure design, security misconfiguration, vulnerable dependencies, authentication failures, integrity failures, logging/monitoring, and SSRF."
license: MIT
---

# OWASP Top 10

Use this as a review checklist. For each category: what to look for in
code, and the fix.

## A01 Broken Access Control
- Look for: handlers that load objects by id without checking ownership (IDOR); admin routes guarded only in the UI; trusting `role` from the client.
- Fix: deny by default; authorise every request server-side against the resource; scope queries (`WHERE id = $1 AND org_id = $2`); test with a second user.

## A02 Cryptographic Failures
- Look for: plaintext secrets, MD5/SHA1 password hashes, HTTP links, custom crypto.
- Fix: TLS everywhere + HSTS; Argon2id/bcrypt/scrypt for passwords; vetted libraries (libsodium); encrypt sensitive data at rest; secrets in a manager.

## A03 Injection
```python
# vulnerable
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
# fixed
cur.execute("SELECT * FROM users WHERE email = %s", (email,))
```
- SQL/NoSQL: parameterised queries only. Shell: avoid `shell=True`; pass argument arrays. XSS: framework auto-escaping, no `innerHTML`/`dangerouslySetInnerHTML` with user data, sanitise rich HTML with DOMPurify, add CSP.

## A04 Insecure Design
- Missing rate limits on login/OTP, no abuse cases, business logic flaws (negative quantities, race conditions on balances).
- Fix: threat-model features; enforce invariants server-side; use transactions/locks for money.

## A05 Security Misconfiguration
- Debug mode in prod, default creds, verbose errors, open S3 buckets, permissive CORS, missing headers.
- Fix: hardened defaults per environment, security headers, IaC review, least privilege.

## A06 Vulnerable and Outdated Components
- Fix: lockfiles, Dependabot/Renovate, `npm audit`/`pip-audit`/`osv-scanner` in CI, remove unused deps.

## A07 Identification and Authentication Failures
- Fix: MFA, credential stuffing protection, secure session cookies (`HttpOnly; Secure; SameSite`), rotate session id on login, generic login error messages.

## A08 Software and Data Integrity Failures
- Unsafe deserialization (`pickle`, Java serialization) of untrusted data; unsigned updates; CI pulling unpinned actions.
- Fix: JSON with schemas; signature verification; pin dependencies and actions by hash.

## A09 Security Logging and Monitoring Failures
- Fix: log auth events, access denials, and admin actions with user and request ids; alert on anomalies; never log secrets or tokens.

## A10 Server-Side Request Forgery
- Look for: fetching user-supplied URLs (webhooks, image proxies, importers).
- Fix: allowlist hosts/schemes; resolve DNS and block private, loopback, link-local, and metadata ranges (169.254.169.254); disable redirects or re-validate; egress firewall.

## Review workflow
1. Map entry points and trust boundaries.
2. Walk each category against those entry points.
3. Record findings with severity, location, reproduction, and fix.
4. Add regression tests for each fixed issue.
