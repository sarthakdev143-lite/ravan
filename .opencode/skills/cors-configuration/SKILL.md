---
name: cors-configuration
description: "Use when configuring or debugging CORS — simple vs preflighted requests, Access-Control-Allow-Origin/Credentials/Headers/Methods, origin allowlists, Vary: Origin, caching preflights, framework/CDN/gateway configuration, and security mistakes like reflecting arbitrary origins."
license: MIT
---

# CORS Configuration

CORS is the browser relaxing the same-origin policy when the **server**
says so. It doesn't protect your API from non-browser clients — it
protects users' browsers from other sites reading responses.

## When to Use This Skill
- "Blocked by CORS policy" errors in the console
- Frontend and API on different origins (ports and subdomains count)
- Security review of CORS headers

## How it works
- **Simple requests** (GET/POST with simple headers/content types) are sent; the browser hides the response unless headers allow it.
- **Preflight**: other methods, `Content-Type: application/json`, or custom headers trigger an `OPTIONS` request first.

```
OPTIONS /api/items
Origin: https://app.example.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: content-type, authorization

204
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: content-type, authorization
Access-Control-Max-Age: 600
Vary: Origin
```

## Configuration
```ts
const allowed = new Set(['https://app.example.com', 'https://admin.example.com']);
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || allowed.has(origin)),
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600,
}));
```
- Exact origin match against an allowlist — no substring or naive regex (`example.com.evil.net`).
- `credentials: true` requires a specific origin, never `*`.
- Send `Vary: Origin` when the response depends on origin so caches don't mix them.
- Expose custom response headers with `Access-Control-Expose-Headers`.

## Debugging
1. Read the exact console message — it names the missing header.
2. Check the preflight in the Network tab: status must be 2xx, with CORS headers.
3. Auth middleware rejecting `OPTIONS` (401) is a common cause; let preflights through.
4. Errors on 500 responses: error handlers often skip CORS headers — add them globally.
5. Proxies/CDNs stripping or caching headers without `Vary`.
6. In development, a dev-server proxy avoids CORS entirely.

## Security mistakes
- Reflecting any `Origin` with `Allow-Credentials: true` → any site can read authenticated data.
- Allowing `null` origin (sandboxed iframes, file URLs).
- Treating CORS as authentication — still authenticate and authorise every request.
- Wildcard `*` is fine only for truly public, unauthenticated resources.
