# Modern attack surfaces — OWASP 2025 delta, API, LLM, ATT&CK

Edition-pinned. Verify against current OWASP/ATT&CK publications before citing
edition numbers in reports.

## OWASP Top 10 2025 delta (vs 2021)

- **A03 Software Supply Chain Failures** (new, replaces vulnerable-components):
  CI/CD integrity, build provenance, malicious packages, maintainer takeover.
- **A10 Mishandling of Exceptional Conditions** (new): fail-open auth,
  error-state abuse, unhandled-path bypass.
- **A02 Security Misconfiguration** rises to #2. **SSRF folds into A01**
  Broken Access Control. Map SSRF findings to access-control language.

## OWASP API Top 10 (2023) — plan-only checklists

- API1 BOLA: object-id swapping across users, the #1 API finding class.
- API2 broken authentication: token theft, reset flows, rate limits.
- API3 BOPLA: property-level over/under-exposure (mass assignment inverse).
- API4 resource consumption: no rate/depth/cost limits.
- API5 BFLA: function-level (admin endpoints reachable by non-admin).
- API6 business-flow abuse: automation of sensitive flows without controls.
- API7 SSRF, API8 misconfiguration, API9 inventory (shadow/versioned APIs),
  API10 unsafe consumption (trusting third-party data).

## OWASP LLM Top 10 (2025)

LLM01 prompt injection · LLM02 sensitive disclosure · LLM03 supply chain ·
LLM04 data/model poisoning · LLM05 improper output handling · LLM06
excessive agency · LLM07 system-prompt leakage · LLM08 vector/embedding
weaknesses · LLM09 misinformation · LLM10 unbounded consumption. Assess
LLM-era apps for these at planning level; Ravan itself must never leak its
own prompt (LLM07 applies to the agent too).

## MITRE ATT&CK tagging

Tag every finding and next step with tactic + technique IDs where known:
reconnaissance TA0043 (T1595 active scanning), initial access (T1190 public
apps), credential access (T1552.005 cloud metadata API via SSRF), defense
evasion, privilege escalation, lateral movement, exfiltration, impact.
Enterprise is 14 tactics / 216 techniques / 475 sub-techniques — cite IDs,
never vibes.

## Per-class planning blocks (preconditions → safe verification)

- **JWT:** alg confusion (`none`, jku/x5u), weak secrets, kid manipulation.
  Safe check: decode header/payload (no verify), inspect `alg`, expiry,
  audience/issuer; never forge tokens for unverified targets.
- **OAuth/OIDC:** redirect_uri + response_mode + state combination review,
  PKCE presence, implicit-flow prohibition. Safe check: config/param
  inspection only.
- **GraphQL:** introspection enabled, nested-query depth, field-level authz.
  Safe check: schema/introspection response review with authorization.
- **WebSockets:** origin validation, auth on upgrade, message-level authz.
- **SSTI:** template-engine identification; inert observable reasoning only
  (e.g. math-evaluation-neutral logic), never exfiltration payloads.
- **XXE:** SVG/SAML/Office upload parsers, external-entity resolution. Name
  it explicitly — it hides inside A05.
- **Prototype pollution:** `__proto__`/merge/cloneDeep sinks; gadget review.
- **Race conditions:** predict → probe → prove methodology note; multi-step
  sequences, limit overruns; parallelized confirmation is operator-run only.
- **Request smuggling / cache poisoning-deception:** architecture-gated
  (front-end/back-end combos); planning notes + operator verification.
- **Cloud SSRF chains:** IMDS endpoints (AWS/GCP/Azure variants), metadata
  → credentials → K8s service-account tokens. Planning-level paths only.
- **K8s/RBAC:** service accounts, cluster-admin bindings, NetworkPolicy
  absence. Review manifests, never touch live clusters.
- **File upload:** MIME sniffing, SVG XSS, polyglots, zip-slip/zip-bomb,
  CSV formula injection.

## Coverage matrix (mandatory in every report's limitations)

Tabulate each class above as covered / partial / absent for this
engagement, with why. Honest scoping beats silent ignorance.
