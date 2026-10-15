# Remediation Library

Tested, copy-pasteable fixes. Each entry notes ordering constraints and failure modes — the
advice that causes incidents is usually the correct action performed in the wrong order.

## Apache / LiteSpeed `.htaccess`

Works on LiteSpeed (which honours Apache directives), most cPanel hosts and Hostinger.
Requires `mod_headers` and `mod_rewrite`, both normally enabled.

### Complete hardening block

```apache
<IfModule mod_headers.c>
  # --- Transport ---
  # Deploy with max-age=300 first. includeSubDomains forces EVERY subdomain to
  # HTTPS-only: verify ftp./mail./autodiscover./autoconfig. serve valid HTTPS first.
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains" env=HTTPS

  # --- Core hardening ---
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
  Header always set Cross-Origin-Opener-Policy "same-origin"

  # 'always' is required, or headers are omitted on 4xx/5xx responses — which is
  # exactly where platform default error pages live.

  # --- Reduce disclosure ---
  Header unset platform
  Header unset panel
  Header unset X-Powered-By
</IfModule>

<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteBase /

  # Force HTTPS (skip if your host already does this)
  RewriteCond %{HTTPS} !=on
  RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

  # Canonicalise www -> apex (or reverse it, but pick ONE)
  RewriteCond %{HTTP_HOST} ^www\.(.+)$ [NC]
  RewriteRule ^ https://%1%{REQUEST_URI} [L,R=301]

  # SPA fallback: serve real files/dirs, everything else -> the shell.
  # Fixes deep-link 404s AND stops the platform default error page being served
  # (which usually carries the host's own analytics tags and no CSP).
  RewriteCond %{REQUEST_FILENAME} -f [OR]
  RewriteCond %{REQUEST_FILENAME} -d
  RewriteRule ^ - [L]
  RewriteRule ^ index.html [L]
</IfModule>
```

### CSP (roll out in Report-Only first)

```apache
<IfModule mod_headers.c>
  # Phase 1: observe. Tune against real violations for ~1 week.
  Header always set Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; report-uri /csp-report"

  # Phase 2: enforce (rename the header, drop -Report-Only)
</IfModule>
```

Adjust per observed dependencies:

- `style-src 'unsafe-inline'` — required by Tailwind runtime injection and most CSS-in-JS.
  Keep `script-src` free of it; that is where the protection lives.
- `connect-src` — add form/API providers (`https://api.web3forms.com`,
  `https://formcarry.com`, your backend origin).
- `form-action` — must include third-party form endpoints or submissions break.
- `frame-src` — add `https://www.google.com` for Maps embeds, or the map disappears.
- `img-src` — add map/CDN origins; `data:` and `blob:` are commonly needed.

### Custom error page (removes host-injected analytics)

```apache
ErrorDocument 404 /index.html      # SPA: let the router render not-found
ErrorDocument 500 /500.html
```

Test after deploying:
```bash
curl -s https://example.com/definitely-not-here | grep -icE 'googletagmanager|doubleclick|bootstrap'
# expect 0
```

## nginx equivalent

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;

server_tokens off;

location / {
  try_files $uri $uri/ /index.html;   # SPA fallback
}
```

`add_header` inherits poorly in nginx — if you add any `add_header` inside a `location`
block, you must repeat the ones you want there.

## DNS records

### SPF

```dns
; Target state. Do NOT switch to -all until DKIM works and every sender is enumerated.
example.com.  TXT  "v=spf1 include:<provider> -all"
```

Sequence: `~all` (monitor) → enumerate senders from DMARC reports → `-all` (enforce).
Switching early silently drops legitimate mail.

### DMARC (three phases)

```dns
; Phase 1 — monitor 2-4 weeks. Create the mailbox FIRST or reports bounce.
_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1; pct=100"

; Phase 2 — quarantine, after reviewing reports for missed legitimate senders
_dmarc.example.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; fo=1; adkim=s; aspf=s; pct=100"

; Phase 3 — target state
_dmarc.example.com.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; fo=1; adkim=s; aspf=s"
```

Add `sp=reject` if subdomains should not send mail at all. Read the `rua` XML reports
between phases — they are the only reliable way to find senders you forgot about.

### DKIM

Generated by your provider; publish the record it gives you. Hostinger: hPanel → Emails →
your domain → DNS settings. Google Workspace: Apps → Google Workspace → Gmail →
Authenticate email. Then verify:

```bash
dig TXT <selector>._domainkey.example.com +short   # expect v=DKIM1; k=rsa; p=...
```

### CAA

```dns
example.com.  CAA  0 issue     "letsencrypt.org"
example.com.  CAA  0 issuewild "letsencrypt.org"
example.com.  CAA  0 iodef     "mailto:security@example.com"
```

⚠️ If you later put Cloudflare or another CDN in front, you **must** add their CAs too or
certificate issuance breaks. Cloudflare's docs list the exact records per plan.

### MTA-STS + TLS-RPT

```dns
_mta-sts.example.com.  TXT  "v=STSv1; id=20261015120000Z;"
mta-sts.example.com.   A    <your web IP>
_smtp._tls.example.com. TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
```

Serve over HTTPS at `https://mta-sts.example.com/.well-known/mta-sts.txt`:

```
version: STSv1
mode: enforce
mx: mx1.example.com
mx: mx2.example.com
max_age: 86400
```

Start with `mode: testing` to collect reports before enforcing. Requires a valid certificate
on `mta-sts.` — a wildcard cert covers it. Do this after DNSSEC.

### security.txt

Serve at `/.well-known/security.txt`:

```
Contact: mailto:security@example.com
Expires: 2027-10-15T00:00:00.000Z
Preferred-Languages: en
Canonical: https://example.com/.well-known/security.txt
Policy: https://example.com/security-policy
```

Sign with GPG if you publish a key (`Encryption:` field). `Expires` is required by RFC 9116
— an expired file is ignored by tooling.

## Build configuration

### Vite — production hardening

```js
// vite.config.js
export default {
  build: {
    sourcemap: false,          // never publish source maps
    minify: 'terser',
    terserOptions: { compress: { drop_console: true, drop_debugger: true } },
    // Or with the default esbuild minifier:
    // esbuild: { drop: ['console', 'debugger'] }
  },
}
```

### Code splitting (makes future analysis possible)

A single concatenated bundle prevents vendor/app separation, which forces signature-only
filtering and makes sink analysis unverified. Splitting is a small config change with a real
payoff at review time:

```js
build: { rollupOptions: { output: { manualChunks: { vendor: ['react','react-dom'] } } } }
```

### Dependency updates

```bash
npm audit --production
npm install react-router@^7.18.0 react@^19.2.5 react-dom@^19.2.5
npm run build          # MUST rebuild — the served bundle is what matters, not package.json
```

Add to CI so drift cannot recur:
```yaml
- run: npm ci
- run: npm audit --audit-level=high --production
```

## Form abuse hardening

Third-party form keys are public by design; the fix is provider-side restriction plus bot
detection, not hiding the key.

**Honeypot** (Web3Forms natively rejects a truthy `botcheck`):
```jsx
<input type="checkbox" name="botcheck" style={{ display: 'none' }} tabIndex={-1}
       autoComplete="off" />
```

**Web3Forms:** dashboard → your form → enable reCAPTCHA/Turnstile **and** set a domain
restriction so only your origin is accepted. Then rotate the access key.

**Formcarry:** enable the spam filter / hCaptcha; set allowed file types and max size in the
dashboard so limits are enforced server-side, not only in JS.

**File uploads to staff:** restrict to `.pdf` only — `.doc`/`.docx` carry macro risk and HR
staff are conditioned by their role to open attachments from strangers. Route to a dedicated
intake address isolated from the general mailbox.

**Longer term:** proxy forms through a serverless function (Cloudflare Workers / Vercel)
that validates input, checks `Origin`, applies rate limiting and holds provider keys
server-side.

## Self-hosting fonts

Removes a third-party request, an SRI problem, and a GDPR concern (loading from
`fonts.googleapis.com` sends visitor IPs to Google).

```bash
# Download the WOFF2 files, place in public/fonts/, then:
```
```css
@font-face {
  font-family: 'Inter';
  src: url('/fonts/inter-var.woff2') format('woff2-variations');
  font-display: swap;
}
```

## Verification commands

```bash
# Headers
curl -sSI https://example.com/ | grep -iE \
 'strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|content-security|^server|platform|panel'

# Headers on error responses too ('always' keyword check)
curl -sSI https://example.com/nonexistent-xyz | grep -ic content-security-policy

# SPA routing — all should be 200
for p in /about /contact /blog; do
  printf '%-12s %s\n' "$p" "$(curl -s -o /dev/null -w '%{http_code}' https://example.com$p)"
done

# Source maps must stay closed (expect 404)
curl -s -o /dev/null -w '%{http_code}\n' https://example.com/assets/index-XXXX.js.map

# Methods (expect 405/501 for TRACE, PUT, DELETE)
for m in TRACE PUT DELETE; do
  printf '%-7s %s\n' "$m" "$(curl -s -o /dev/null -w '%{http_code}' -X $m https://example.com/)"
done

# Email authentication
dig TXT _dmarc.example.com +short
dig TXT example.com +short
dig CAA example.com +short
dig DS  example.com +short

# TLS
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -dates -subject -issuer
```

Third-party validators (no install):
- https://securityheaders.com — target grade A
- https://observatory.mozilla.org — target 90+
- https://www.ssllabs.com/ssltest/ — target A or better
- https://dmarcian.com/domain-checker/ · https://www.mail-tester.com — email auth
- https://dnsviz.net — DNSSEC chain validation
