# Hardening matrix — copy-paste blocks per stack

Staged rollout always. Irreversible steps are marked irreversible.

## CSP (nonce/hash migration, never perpetual unsafe-inline)

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$NONCE'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests
```

- Report-Only first with `report-to` endpoint, fix violations, then enforce.
- Trusted Types for DOM-XSS-prone apps: `require-trusted-types-for 'script'`.
- Per framework: Next.js `headers()` in config; Django `django-csp`;
  Spring `ContentSecurityPolicyHeaderWriter`; Express `helmet.contentSecurityPolicy`.

## HSTS ramp (blast radius: breaks insecure subdomains)

1. `max-age=300` → verify all subdomains serve valid HTTPS.
2. `max-age=86400` → hold one week, monitor.
3. `max-age=31536000; includeSubDomains` → hold.
4. `preload` token + hstspreload.org submission — effectively
   IRREVERSIBLE for months. Inventory every subdomain first.

## Cookies

- `__Host-session=...; Secure; HttpOnly; SameSite=Lax; Path=/`
  (`__Host-` requires Secure + Path=/ + no Domain — strongest).
- `SameSite=None` requires `Secure`. `Partitioned` (CHIPS) for
  cross-site-embedded contexts.
- Sessions: rotate on login, absolute + idle timeouts, server-side
  invalidation. JWT in HttpOnly cookie, never localStorage.

## CORS (allowlist, never reflect-then-trust)

- Explicit `Access-Control-Allow-Origin: https://app.example.com` (no `*`
  with credentials), `Vary: Origin`, reject `null` origins, cache preflights
  briefly. Express `cors({origin})`, Django `CORS_ALLOWED_ORIGINS`, Spring
  `CorsConfiguration`.

## TLS

- Floor TLS 1.2, prefer 1.3. AEAD-only ciphers; kill RC4/3DES/CBC/DES and
  `TLS_RSA_*`. `ssl_prefer_server_ciphers on` (nginx). OCSP stapling +
  Must-Staple where possible. ACME auto-renewal (90-day certs), CT-log
  monitoring, key rotation runbook. Warn: TLS 1.3 0-RTT replay risk.

## Reverse proxies / edge

- Apache/nginx: strip `Server`/`X-Powered-By`, add full header set.
- Caddy/Traefik: header middleware equivalents. Cloudflare: Transform
  Rules. Vercel/Netlify: `_headers` / response policies. S3+CloudFront:
  response-header policies. Always configure trusted-proxy
  (`X-Forwarded-*` spoofing otherwise).

## Fetch-metadata isolation

`Cross-Origin-Embedder-Policy: require-corp` (staged — breaks embeds),
`Cross-Origin-Opener-Policy: same-origin`,
`Cross-Origin-Resource-Policy: same-origin`,
`Origin-Agent-Cluster: ?1`. `Cache-Control: no-store` on authenticated
pages; `Clear-Site-Data` on logout. SRI `integrity=` + `crossorigin` on
third-party scripts; rotate hash on every upgrade.

## Framework secure defaults (checklist)

- Next.js: `poweredByHeader: false`, `headers()`, middleware auth order.
- Django: `SECURE_SSL_REDIRECT`, `SECURE_HSTS_*`, `DEBUG=False`,
  `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, `SESSION_COOKIE_*`.
- Spring: `headers()`, actuator exposure off, CSRF config.
- Laravel: `APP_DEBUG=false`, Sanctum config, `.env` never committed.
- Express: `helmet()`, `express-rate-limit`, `trust proxy` set correctly.
- Rails: `force_ssl`, `config.ssl_options`. FastAPI: `TrustedHostMiddleware`.

## Email + standards

- SPF/DKIM/DMARC monitor → quarantine → reject (see agent). MTA-STS
  testing + TLS-RPT monitoring ≥2 weeks → enforce. `security.txt`
  (RFC 9116, `Expires`, sign with `Encryption:` key).
