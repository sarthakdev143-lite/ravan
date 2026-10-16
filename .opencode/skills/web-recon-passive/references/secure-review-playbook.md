# Secure review playbook — source→sink tables + checklists

A finding requires taint reaching a sink. Candidate matches without a path
are `gated`. Cite file:line + 5-line excerpt max.

## JS/TS

| Source | Sink | Safe pattern |
|---|---|---|
| `req.query/body/params`, `location.hash`, `postMessage` data | `innerHTML`/`outerHTML`/`document.write`, `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*` | textContent, framework escaping, DOMPurify + Trusted Types |
| user input | `eval`, `Function(`, `vm.run*`, `ejs.render(user)` | no dynamic codegen; `JSON.parse` for data |
| user input | `child_process.exec/execSync`, `fs` + `path.join` traversal | `execFile` argv arrays, canonicalize + allowlist |
| JWT string | `jsonwebtoken.verify` without `algorithms` allowlist | explicit `algorithms: ['RS256']`, check exp/aud/iss |
| deep-merge | `__proto__` pollution via `merge`/`cloneDeep` | frozen prototypes, allowlisted keys |
| URL param | `res.redirect(url)`, `target=_blank` without `noopener` | allowlisted redirects, `rel=noopener` |

## Python

| Source | Sink | Safe pattern |
|---|---|---|
| `request.args/form/json` | `cursor.execute(f"...")`, `os.system`, `subprocess(shell=True)`, `eval`/`exec` | parameterized queries, `shlex` + `shell=False` |
| uploaded/remote data | `pickle.loads`, `yaml.load`, `marshal`, `shelve` | `json`, `yaml.safe_load` |
| URL param | `requests.get(url)` (SSRF) | allowlist + no-metadata-IP guard |
| template vars | `render_template_string`, `mark_safe`/`\|safe` (SSTI/XSS) | context templates, autoescape on |
| secrets | `random`, `hashlib.md5` for passwords | `secrets`, argon2/bcrypt |

## Java / PHP / Ruby / Go / .NET (condensed)

- **Java:** `@RequestParam` → `Statement`/JPQL concat/`ObjectInputStream`/Jackson default-typing/`DocumentBuilder` XXE/Thymeleaf `th:utext`/actuator exposure/JNDI patterns. Fix: prepared statements, Jackson allowlist typing, XXE-disabled parsers.
- **PHP:** `$_GET` → `unserialize`/`eval`/`system`/`exec`/backticks/`include($_GET)`/`extract()`/Laravel `{!! !!}`/`DB::raw`. Fix: `json_decode`, no dynamic include, `htmlspecialchars`, query builder.
- **Ruby:** `params` → `ERB…result(binding)`/`html_safe`/`raw`/`where("…#{…}")`/`YAML.load`/`Marshal.load`/`open()` SSRF. Fix: parameterized `.where`, `YAML.safe_load`, `URI` allowlists.
- **Go:** `r.URL.Query` → `text/template` (use `html/template`), SQL concat, `os/exec` with shell, `filepath.Join` traversal, `encoding/gob`. Fix: parameterized DB, `exec.Command` argv, canonical paths.
- **.NET:** `Request.Query` → `Html.Raw`/`FromSqlRaw` concat/`BinaryFormatter`/`TypeNameHandling.All`/`XmlDocument` XXE/JWT `ValidateIssuerSigningKey=false`. Fix: `Html.Encode`, EF parameters, `System.Text.Json`, hardened `XmlReader`.

## Auth / session / crypto checklist

- OIDC/OAuth scope validation, `redirect_uri` allowlist, PKCE, `state`,
  no implicit flow. JWT: no `alg:none`, verify exp/aud/iss.
- Passwords: argon2id/bcrypt, never MD5/SHA1; MFA/passkeys preferred;
  rate-limit + lockout; session fixation (rotate on login), absolute/idle
  timeouts, concurrent-session policy; CSRF per framework.
- Crypto: CSPRNG per language, no custom crypto, AES-GCM over CBC,
  no ECB/IV-reuse, keys in KMS/Vault never repo/env-commit.

## File / SSRF / traversal / API checklist

- Uploads: allowlist types, canonicalize paths, zip-slip/bomb guards, SVG
  XSS treatment, CSV formula-injection (`=`/`+` prefix escaping),
  `Content-Disposition` for downloads.
- SSRF: metadata-IP deny (`169.254.169.254`, GCP/Azure variants), redirect
  allowlists, response-size/time caps.
- API: BOLA/BFLA/BOPLA tests, mass-assignment blocklist, excessive-data
  trimming, pagination/rate limits, GraphQL introspection off + depth
  limits, webhook HMAC verification, idempotency keys.

## IaC / containers

- **Terraform/CFN:** no `0.0.0.0/0` SG, encrypted S3/RDS/EBS, no public
  buckets, no IAM `*:*`, versioning + MFA-delete, state secrets. Tools:
  Checkov/tfsec.
- **K8s:** no `privileged`/`hostNetwork`/`hostPID`/`runAsRoot`, drop
  capabilities, `readOnlyRootFilesystem`, seccomp, NetworkPolicy
  default-deny, no secrets-in-env, no `cluster-admin` bindings, no `:latest`.
  Tools: KubeLinter/Trivy.
- **Docker:** non-root `USER`, multi-stage/distroless, no secrets in
  layers/`ENV`, no `--privileged`, signed bases.

## CI/CD

GHA pin-to-SHA, least-privilege `permissions:`, OIDC not long-lived tokens,
`pull_request_target` injection awareness, branch protection + CODEOWNERS,
gitleaks/trufflehog pre-commit + push protection, cosign/SLSA signing,
Dependabot/Renovate, `npm ci --frozen-lockfile`, ZAP-baseline/Nuclei on
staging.
