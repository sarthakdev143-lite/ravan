# Ravan Power-Features Gap Audit — automation, workflows, memory, integrations, UX

Ground truth (read first, all local): `ravan` today is one agent file (`.opencode/agents/ravan.md`,
`mode: all`, ordered allow/ask/deny permissions), one skill (`web-recon-passive`, stdlib-only Python,
DNS/TLS/headers/JS-bundle/CVE checks, GHSA+NVD correlation, 42 offline unit tests), and an effectively
empty `opencode.jsonc` (only `$schema`). No custom commands, no MCP servers, no companion subagents,
no `instructions` files, no finding memory, no scheduled/retest loop. Everything below maps each
proposal to a concrete artifact path.

## Which OpenCode primitives are unused and would 10x power

### Takeaway

Ravan uses ~2 of ~7 V2 composition primitives (agent + skill); the empty `opencode.jsonc` plus the
absence of `commands/`, `instructions`, MCP servers, and companion subagents is the single largest
power gap — all are cheap Markdown/JSON artifacts.

### Cited Findings

- Custom commands are Markdown files in `.opencode/commands/` (per-project) or
  `~/.config/opencode/commands/` (global); the filename becomes the command name and content is sent
  as the message; named `$PLACEHOLDER` args prompt for values; they can also be defined inline under
  the `command` key in config — [Source](https://opencode.ai/docs/commands)
- MCP servers are configured under the `mcp` key in `opencode.json(c)`; local servers use a `command`
  array (OpenCode launches the process), remote servers use a `url` + OAuth; project config overrides
  global; managed via `opencode mcp add/list/auth` —
  [Source](https://composio.dev/content/mcp-with-opencode); [Source](https://opencode.ai/docs/config)
- The GitHub MCP server supports toolset limiting (`X-MCP-Toolsets` header / `--toolsets` flag) to
  control context bloat; OpenCode docs explicitly warn it "can add a lot of tokens to your context" —
  [Source](https://github.com/github/github-mcp-server/blob/main/docs/installation-guides/install-opencode.md)
- Subagents are Markdown files in `.opencode/agents/` with `mode: subagent`, run in fresh-context
  child sessions, invokable by `@mention` or auto-selected from their `description`; the parent's
  `subagent`-action permission rules control which children it may launch; V2 builtins are
  `build`/`plan` (primary) and `general`/`explore` (subagent); there is no V2 `scout` —
  [Source](https://opencode.ai/v2/docs/agents)
- Agent `permissions` are an ordered allow/ask/deny list where the last matching rule wins; valid
  actions include `shell`, `edit`, `subagent`, `read`/`glob`/`grep`, `webfetch`/`websearch`, `skill`;
  legacy keys (`temperature`, `tools`, `permission`, `prompt`, `maxSteps`) are forbidden in V2 —
  [Source](https://opencode.ai/v2/docs/agents) (ravan.md already complies — local:
  `.opencode/agents/ravan.md:1-130`)
- Project guidance comes from `AGENTS.md` (global + project-root, both loaded) plus extra files
  listed under the `instructions` key in `opencode.json`, including remote URLs (5s fetch timeout) —
  [Source](https://opencode.ai/docs/rules); [Source](https://opencode.ai/v2/docs/instructions)
- Semgrep ships an MCP server (`uvx semgrep-mcp`, stdio) exposing `security_check`, `semgrep_scan`,
  `semgrep_scan_with_custom_rule`, `get_abstract_syntax_tree`, `semgrep_findings` (AppSec Platform
  token), `supported_languages`, `semgrep_rule_schema`, plus `semgrep://rule/…` resources; backed by
  5000+ rules; the standalone repo is archived and the server now ships inside the main `semgrep`
  binary/repo — [Source](https://github.com/semgrep/mcp); Semgrep Guardian bundles MCP server +
  hooks + skills for scan-on-generate loops — [Source](https://semgrep.dev/products/semgrep-guardian)

### Inferences

- Concrete artifact map (all currently missing, all additive):
  - `.opencode/commands/threat-model.md` (`/threat-model $TARGET`), `review.md` (`/review` — diff/changed-file review), `harden.md` (`/harden $AREA` — CSP/HSTS/cookies/TLS/email-auth), `retest.md` (`/retest $FINDING_ID` — verification loop), `roe.md` (`/roe $TARGET` — Rules-of-Engagement generator). Each is one Markdown file with `$PLACEHOLDER` args per the commands doc.
  - `opencode.jsonc`: add `mcp` (Semgrep local via `uvx semgrep-mcp`; GitHub remote with toolsets restricted to advisories/repos read-only), `instructions` (finding-ledger schema, severity rubric, remediation library index), `default_agent: ravan` (already documented as optional in local `README.md:60-66`).
  - `.opencode/agents/ravan-recon.md` (`mode: subagent`, run recon skill, return JSON facts only), `ravan-reviewer.md` (read-only code review, `edit: deny`, `shell: deny`), `ravan-reporter.md` (finding JSON → business report). Parent ravan keeps `subagent: * allow` (already present — local `ravan.md:35-37`) and fans out recon/reviewer/reporter in parallel.
  - `AGENTS.md` or `instructions`-referenced `security-profile.md`: per-project stack, trust boundaries, known-accepted risks — loaded every session without re-prompting.
- Semgrep MCP is the highest-leverage MCP add: it converts ravan code review from grep-opinion to deterministic 5000-rule SAST with finding output the agent can re-rank; keep it local-stdio (no data leaves the machine) and gate `semgrep_findings` (cloud) behind `ask`.
- GitHub MCP must be toolset-limited (advisory/repos read-only) per the token-bloat warning, and ravan's `question`-based authorization gate must extend to it (read-only advisory reads = fine; repo enumeration of third parties = out-of-scope default).

### Gaps

- I found no reliable source on OpenCode V2 cron/scheduled-session primitives (needed for "scheduled sweeps"); if absent, scheduling must live outside OpenCode (OS cron invoking headless runs) — flag to verify against `opencode run` docs.
- I found no official OSV MCP server; OSV access is REST (`api.osv.dev`) so it maps to a custom tool or `webfetch` recipe, not an MCP entry — worth one verification search.

## What workflows are missing: intake, RoE, retest, sweeps, SBOM watch, baseline-diff

### Takeaway

Ravan's skill defines a single one-shot passive run (authorize → scan → JSON + Markdown); the missing
layer is everything around it — structured intake, RoE generation, fix-verification loops, periodic
re-sweeps with diffing, and continuous dependency watching. Each maps to one command or script file.

### Cited Findings

- The skill's CLI enforces an authorization gate (`--i-am-authorized` mandatory, exit 2 without it,
  `--contact` baked into User-Agent) and a request budget with inter-request delay — local:
  `.opencode/skills/web-recon-passive/README.md:43-87`; the agent prompt requires `question`-tool
  confirmation when ownership is unclear — local: `.opencode/agents/ravan.md:198-201`
- The skill outputs declarative JSON facts plus a Markdown report and explicitly defers re-ranking and
  narrative to the calling agent ("hardcoded narrative prevents that") — local:
  `.opencode/skills/web-recon-passive/README.md:148-159`
- OpenCode custom commands accept `$PLACEHOLDER` arguments that prompt for values at invocation —
  [Source](https://opencode.ai/docs/commands); subagents run in child sessions with fresh context and
  return results to the parent — [Source](https://opencode.ai/v2/docs/agents)
- OSV provides a keyless REST API (`api.osv.dev`) for known-vulns-by-package-version/purl/commit,
  batch checks of up to 100 dependencies, and full records by OSV/GHSA/CVE id, aggregating GHSA,
  PyPI, Go, RustSec, NVD, Debian sources — [Source](https://www.firecrawl.dev/alexandria/osv-dev);
  OSV-Scanner handles lockfiles, SPDX/CycloneDX SBOMs, and git repos —
  [Source](https://github.com/google/osv.dev)
- No single vuln database is complete: in a 1000-advisory 2024–2025 sample, NVD covered 89%, OSV 93%,
  GHSA 87%, and their union 98% (vendor study, treat as directional not canonical) —
  [Source](https://safeguard.sh/resources/blog/open-source-vulnerability-database-comparison)

### Inferences

- Concrete workflow → artifact map:
  - Guided intake: `.opencode/commands/assess.md` (`/assess`) — fixed question flow (target, ownership proof, scope in/out, stack, data sensitivity, contact) answered via the `question` tool (already allowlisted — local `ravan.md:29-31`), writes `.opencode/security/intake-$TARGET.md`; no scan starts without it.
  - RoE generator: `.opencode/commands/roe.md` (`/roe`) — emits targets in/out, allowed/forbidden methods, windows, data handling, contacts, stop conditions (categories already enumerated in local `ravan.md:165-167`), saved as `ROE-$TARGET.md` requiring explicit user sign-off.
  - Retest/verify loop: `.opencode/commands/retest.md` (`/retest $FINDING_ID`) — re-runs only the checks covering one finding id from the ledger, compares evidence, marks `fixed`/`persists`/`regressed`; pairs with the skill's JSON-facts design (machine-diffable by construction).
  - Scheduled sweeps: no native primitive found → `scripts/sweep.sh` + OS cron invoking headless one-shot runs, results appended to the ledger; document as external-scheduler pattern rather than pretending config supports it.
  - SBOM + advisory watch: `scripts/depwatch.py` (stdlib-only, mirroring skill conventions) — parse lockfile/SBOM → batch-query `api.osv.dev` (100/batch) → enrich with KEV/EPSS (see §4) → append `dependency` findings to the ledger; `cve.py` (GHSA+NVD) already exists — local `README.md:131-140` — so this extends rather than replaces it.
  - Baseline-then-diff: every report run writes `reports/$TARGET/$DATE.json`; a `scripts/diff.py` (or `/retest`-adjacent command) emits new/fixed/persisting findings between baselines — the highest-value reporting upgrade for repeat engagements.

### Gaps

- Whether OpenCode V2 supports unattended/headless invocation (`opencode run`) with ravan pre-selected for cron use — needs a docs check; without it, scheduled sweeps require manual sessions.
- No source found on Nuclei template-metadata consumption patterns for agents (read-only interpretation of others' scan output is the safe shape, but the template schema fields worth parsing need one targeted lookup).

## What memory and learning is absent: history, false positives, profiles, calibration, evals

### Takeaway

Ravan is stateless across sessions: severity calibration, false-positive suppressions, and
target-specific knowledge all evaporate when the session ends. The skill's offline test suite is a
strong eval seed, but there is no finding ledger, no suppression list, and no project profile — three
small Markdown/JSON files plus an eval-extension would fix it.

### Cited Findings

- The skill pins every false-positive filter with a test: "If you add a pattern to `checks.py`, add a
  fixture to `test_checks.py` proving it does not fire on react-dom"; 42 offline unit tests + 16
  replay checks against a captured real bundle — local:
  `.opencode/skills/web-recon-passive/README.md:109-121`
- The agent prompt already mandates a false-positive appendix ("what was checked and rejected, with
  reasons… the strongest credibility signal") and target-recalibrated severity — local:
  `.opencode/agents/ravan.md:258-281`
- OpenCode loads project guidance from `AGENTS.md` plus `instructions`-listed files every session, so
  file-based memory is loaded automatically with no plugin code —
  [Source](https://opencode.ai/docs/rules); [Source](https://opencode.ai/v2/docs/instructions)
- Semgrep Guardian's hook pattern (scan-on-file-write, regenerate-until-clean-or-dismissed) shows the
  dismiss/suppress decision as a first-class persisted signal —
  [Source](https://docs.semgrep.dev/semgrep-guardian/overview)

### Inferences

- Concrete memory → artifact map (all file-based, stdlib-friendly):
  - `.opencode/security/findings.jsonl` — append-only finding ledger (id, target, check, severity, status, evidence ref, first-seen, last-seen); powers retest loops, baseline diffs, and "previously seen" dedup.
  - `.opencode/security/suppressions.md` — rejected positives with reason + evidence hash (e.g. "react-router localhost fallback — signature-filtered, method: signature-only"), referenced by `instructions` so future sessions skip re-flagging without re-reasoning.
  - `.opencode/security/profile.md` (via `instructions`) — per-target calibration: architecture class (static SPA / SSR / API), what is impossible (no SQLi/RCE/SSRF on static SPA — local `ravan.md:227-231`), accepted risks, severity overrides (email-auth up-weighted on small-business sites — local `ravan.md:259-261`).
  - Eval harness: extend `test_checks.py` with adversarial fixtures per FP class (the README table of 12+ real FPs is a ready-made fixture list — local `README.md:89-108`) plus a `tests/golden/` pair of anonymized before/after reports asserting severity-recalibration and done-well sections render; run in CI on every skill change.
- Per-target calibration should be explicit and versioned (profile file diff = audit trail of why severity changed), never silent prompt drift.

### Gaps

- I found no OpenCode-native long-term memory primitive (vector store / memory MCP in core V2 docs surveyed); file-based memory under `instructions` is the confirmed-supported path — a dedicated memory MCP (e.g. community servers) needs a separate evaluation for trust/scope reasons.
- Optimal ledger schema (OSV vs SARIF vs custom JSONL) for diffing + MCP ingestion is undecided; SARIF would interoperate with GitHub code scanning if the GitHub MCP path is pursued.

## What integrations matter most (read-only safe)

### Takeaway

Prioritize keyless, read-only, no-exfiltration feeds that enrich rather than probe: OSV + KEV + EPSS
for dependency verdicts, crt.sh for passive subdomain/CT context — all callable via `webfetch`/stdlib
today with zero MCP trust surface; reserve MCP for Semgrep (local) and GitHub Advisory (read-scoped),
and treat Shodan/Censys/SecurityTrails as key-gated optionals, not core.

### Cited Findings

- CISA KEV is a free public JSON feed, no authentication, listing CVEs with confirmed in-the-wild
  exploitation; practitioners combine KEV membership with EPSS score (FIRST `api.first.org`, also
  keyless) and CVSS to separate same-day incidents from zero-action items —
  [Source](https://www.cisa.gov/resources-tools/resources/kev-catalog);
  [Source](https://www.decryptiondigest.com/blog/cisa-kev-automated-alerts-guide)
- KEV + EPSS integrations require no API key and refresh daily; KEV membership signals urgent
  attention, EPSS gives 30-day exploitation probability —
  [Source](https://docs.invicti.com/appsec/cisakev-epss-integration)
- OSV.dev API is keyless and returns package-version vulnerabilities with source database and license
  attribution per record — [Source](https://www.firecrawl.dev/alexandria/osv-dev); GitHub Advisory
  entries are published as OSV-format JSON and the advisory repo is free/open-source —
  [Source](https://docs.github.com/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database);
  [Source](https://github.com/github/advisory-database)
- crt.sh (Sectigo-operated) is a free CT-log search with a keyless JSON endpoint
  (`?output=json`); `%.domain` wildcard queries enumerate subdomains that ever held a cert; no rate
  limit published but polite spacing is expected — [Source](https://dev.to/0012303/crtsh-has-a-free-api-find-every-ssl-certificate-for-any-domain-with-python-2nlk);
  [Source](https://www.subdomainsfinder.com/crtsh-alternative)
- The existing skill already correlates GitHub Advisory DB + NVD with exploitability gating (not raw
  version-range matching) — local: `.opencode/skills/web-recon-passive/README.md:64-76`

### Inferences

- Integration priority (read-only safe first) with artifacts:
  1. **KEV + EPSS enrichment** (`scripts/cve.py` extension or `scripts/enrich.py`): every dependency/CVE finding gets `kev: bool` + `epss: 0–1` + `exploitable|gated` verdict; KEV-listed + high-EPSS becomes the top of the roadmap automatically. Keyless, stdlib `urllib` + `json`, cache feeds locally with timestamps. Biggest severity-signal upgrade per line of code.
  2. **OSV batch queries** (`scripts/depwatch.py`): replace/augment single-source lookups with `api.osv.dev` batch (100/batch) + GHSA + NVD union (98%-coverage argument above); record per-record source database for attribution.
  3. **crt.sh CT context** (skill `checks.py` addition): passive subdomain/issuer/expiry enrichment for attack-surface mapping — read-only public records, no authorization question needed, but findings must carry the wildcard-DNS caveat already in local `ravan.md:253`.
  4. **Semgrep MCP** (local stdio, `uvx semgrep-mcp`): deterministic SAST for code review; safe because code never leaves the machine; see §1 config.
  5. **GitHub Advisory via MCP or REST** (read-scoped, toolset-limited): human-reviewed advisory text + precise affected ranges for remediation specificity.
  6. **Nuclei template metadata, read-only**: parse template YAML (severity, tags, CVE refs) to *interpret* operator-provided Nuclei output and to draft scan plans — never to execute (execution stays denied — local `ravan.md:129`).
  7. **Shodan/Censys/SecurityTrails**: optional, key-gated, third-party-by-default-out-of-scope (local `ravan.md:202-204`); only query the target's own assets post-authorization. Document as `docs/integrations.md` with key setup, not core config.
- Explicit non-goals: no authenticated probing, no form submission, no exploit fetching (metasploit-db-as-reference stays conceptual/planning-level per local `ravan.md:168-171`).

### Gaps

- NVD API key requirements/rate limits (post-2023 NVD moved to key-gated higher limits) were not re-verified; `cve.py`'s current NVD handling may already degrade silently — needs a code read + one docs check.
- EPSS/KEV feed caching policy (TTL, offline fallback) for the stdlib-only offline-testable convention needs a design decision consistent with the skill's 42-test offline suite.

## What would make UX wise: calibrated severity, done-well, ordered fixes, legal steering

### Takeaway

Ravan's prompt already contains unusually wise UX rules (architecture-before-severity, done-well
sections, ordered remediation with failure modes, practice-environment steering); the gap is
enforcement — these are prompt aspirations today, and they become reliable only as templates,
checklists, and gates the agent cannot skip.

### Cited Findings

- The agent mandates: architecture-impossibility statements, exploitable-vs-gated CVE verdicts with
  reasoning, vendor-vs-app chunk separation for minified JS, public-by-design key labelling,
  wildcard-DNS checks, 405/501 method discipline, target-recalibrated severity, done-well sections,
  exact-directive remediation with failure modes (HSTS `includeSubDomains` breakage, SPF/DMARC
  sequencing), and limitations statements — local: `.opencode/agents/ravan.md:223-272`
- The mandated report shape is Scope/methodology/limitations → Executive summary → Findings table →
  Detailed findings → Done-well → Prioritized roadmap (now/next/later + effort) → Verification
  checklist → Appendices (advisories, logs, rejected positives) — local:
  `.opencode/agents/ravan.md:281-284`; reporting depth lives in `references/reporting-guide.md` and
  fixes in `references/remediation-library.md` (lazy-loaded on demand to save context) — local:
  `.opencode/skills/web-recon-passive/README.md:123-146`
- Email-auth sequencing is explicitly guarded: never recommend SPF `-all` or DMARC `p=reject` first;
  monitor → quarantine → reject — local: `.opencode/agents/ravan.md:185-187`
- Legal steering is a behavioral rule: push hands-on offensive practice to Web Security Academy,
  TryHackMe, HTB, OverTheWire, VulnHub, and in-scope bug bounties; offer study plans and scoped labs —
  local: `.opencode/agents/ravan.md:220-221`

### Inferences

- UX enforcement → artifact map (turn aspirations into gates):
  - `references/report-template.md` — the §-mandated report shape as fill-in sections with per-section checklists (every finding MUST have evidence + mechanism + target-terms impact + exact fix + verification command); the reporter subagent renders it, the parent refuses to deliver prose-only reports.
  - `references/severity-rubric.md` — architecture × exposure matrix (e.g. clickjacking: brochure=low, working-form=medium; weak email-auth on small-business=high) so recalibration is reproducible, not mood-based; cited per finding ("severity recalibrated: reason").
  - `references/remediation-library.md` already exists in the skill — promote it to `instructions` and extend each entry with failure modes + rollback (HSTS preload, SPF `-all`, DMARC reject sequencing already specified locally; add CSP staged-rollout and CAA record syntax).
  - Intake-time legal steering: `/assess` branches — owns-target → engagement path; learning-only → practice-lab path (study plan + lab, per the steering rule) so "how do I hack" prompts always land somewhere legal and useful.
  - Done-well + limitations as blocking checklist items in the report template (a report without both is rejected by the reporter's own instructions) — this is the credibility feature scanners cannot copy.
  - Effort-tagged roadmap (now/next/later + effort) fed by KEV/EPSS enrichment (§4): KEV-listed + exposed = now; gated CVEs scanners will flag = later-with-explanation.

### Gaps

- No comparative source was found on 2025–2026 AI security-agent report UX (what practitioners actually act on); the proposals above derive from ravan's own battle-tested rules rather than external UX studies — a targeted practitioner-interview or report-teardown study would strengthen this.
- Tone calibration guidance (non-alarmist, business-terms impact) exists as prompt prose; whether `question`-tool friction during intake degrades UX vs. a single intake form command is untested — needs real-session feedback.
