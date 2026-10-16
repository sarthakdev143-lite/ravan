# Ravan Agent Architecture Gap Audit

## 1. Permission Design Flaws

### Takeaway
Ravan's permission list is a read-mostly allowlist wrapped around an `ask` default with a narrow, Unix-centric deny block; it suffers from redundant rules, Windows-blind spots, shell-prefix evasion risk, and an `edit=ask` setting that blocks its own core reporting job.

### Cited Findings
- Ravan sets `edit: * → ask`, so every report file it writes prompts the user, despite reporting being its primary output job — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md); elite V2 pattern is a read-only reviewer using `edit: * → deny` plus `shell: * → deny` (e.g. the canonical reviewer example) — [Source](https://v2.opencode.ai/docs/agents)
- Ravan's deny block covers only `rm -rf`, `mkfs`, `dd`, `nmap`, `nikto`, `sqlmap`, `hydra`, `metasploit`, `msfconsole`, `gobuster`, `ffuf`, `nuclei` — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md); it omits entire scanner/enumeration classes (`masscan`, `zmap`, `amass`, `subfinder`, `dirsearch`, `dirb`, `wfuzz`, `feroxbuster`, `nuclei` covered but not `naabu`/`httpx`/`katana`), credential-attack tooling (`john`, `hashcat`, `medusa`, `ncrack`, `nessus`, `openvas`), and any Windows-native living-off-the-land vectors (`powershell Invoke-WebRequest/Invoke-Mimikatz`, `certutil`, `bitsadmin`) despite the project living on Windows (`win32`, PowerShell install docs) — [local README.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\README.md)
- V2 evaluates permission rules with last-match-wins ordering ("put broad wildcard rules first and exceptions afterward") — [Source](https://v2.opencode.ai/docs/agents); ravan's broad `shell: * → ask` comes first with allows after, which is correct ordering, but shell resources are matched as raw command text with no `~`/`$HOME` expansion and no documented whole-command-vs-prefix semantics — [Source](https://v2.opencode.ai/docs/agents) — so allows like `curl -sSI *` and `cat *` are evadable via chaining (`curl -sSI <url> ; <payload>`, `cat file; powershell ...`) unless the runner tokenizes strictly
- Ravan allowlists shell `cat *`, `ls *`, `grep *` — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md) — which duplicate the already-allowed `read`, `glob`, `grep` tools and widen the shell surface for zero capability gain
- Ravan grants `subagent: * → allow` — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md); the V2 child "uses its own configured permissions, not a restricted copy of the parent's permissions" — [Source](https://v2.opencode.ai/docs/agents) — so ravan can spawn any agent (including broad-access `general`) with that agent's full permissions, and elite practice is deny-all-then-allow-named (`subagent * deny` + `subagent reviewer allow`) as shown in the orchestrator example — [Source](https://v2.opencode.ai/docs/agents)
- Ravan grants both `skill: web-recon-passive → allow` and `skill: * → allow` — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md); the second makes the first dead text and silently opts into every future skill installed globally, defeating least-privilege skill scoping
- Ravan grants `question: * → allow` unconditionally — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md); combined with `shell: * → ask` + `edit: * → ask`, a normal passive-review run (write JSON/MD outputs, run recon scripts from non-allowlisted cwd paths) produces repeated approval prompts — ask-fatigue that trains the user to click through, which is exactly the failure mode V2's `--auto` flag weaponizes since auto-approve honors everything not explicitly denied — [Source](https://open-code.ai/en/docs/permissions)
- Shell allows hardcode `python* skills/web-recon-passive/scripts/*` and `python* .opencode/skills/web-recon-passive/scripts/*` path prefixes — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md); any global install (`~/.config/opencode/agents/ravan.md` per README install path), renamed checkout dir, or absolute-path invocation falls outside the allowlist and degrades to `ask` — [local README.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\README.md)
- No `read` deny for `*.env`, secrets, or credential paths; V2's own canonical example denies `read *.env` and build's default policy "asks for .env reads" — [Source](https://v2.opencode.ai/docs/permissions); ravan's behavioral rule 5 ("do not touch discovered credentials") is prompt prose with zero permission enforcement behind it

### Inferences
- SEV-CRITICAL: deny-list is Unix-only on a Windows-hosted project; a prompt-injected or drifted ravan retains silent access to Windows exfil/download primitives and unlisted scanners through the `ask` fallback, which `--auto` mode converts to silent allow.
- SEV-HIGH: `edit: * → ask` directly taxes the agent's defining output (reports); fix is `edit: reports/**/*.md + <out>/**/*.md → allow`, `edit: * → ask` retained, or `deny` outside report paths for a hardened reviewer profile.
- SEV-HIGH: `subagent: * → allow` + child-keeps-own-permissions = privilege-laundering path; fix is deny-all + allow only named least-privilege subagents.
- SEV-MEDIUM: redundant `skill: * allow`, `cat/ls/grep` shell allows, and path-fragile python allows are hygiene debt; collapse to minimal explicit allows.
- SEV-MEDIUM: missing `read` denies on secrets material means the strongest credential-handling rule is unenforceable prose.

### Gaps
- Could not verify from docs whether V2 shell resource matching is prefix, glob-full-match, or token-aware; the chaining-evasion claim depends on this and needs a live permission-probe test.
- No source found confirming whether `ask` rules can carry rationale/conditions in V2 (e.g. ask-with-message); assumed not.

## 2. Elite Agent Structure (Modes, Steps, Models, Colors, Hidden Agents, Question Tool)

### Takeaway
Ravan is a single monolithic `mode: all` agent with no model pin, no steps budget, no color, and no supporting cast; every elite reference design (V2 builtins, Semgrep's pipeline agents, Burp AI's scanners, community orchestrator packs) decomposes into a least-privilege team with bounded steps and explicit models.

### Cited Findings
- Ravan declares only `description` + `mode: all`, with no `model:`, `steps:`, `color:`, or `hidden:` keys — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md); V2 supports all four (`model: provider/model#variant`, `steps:` positive int with tools stripped on final step, `color:` six-digit hex, `hidden:` visibility flag) — [Source](https://v2.opencode.ai/docs/agents)
- V2's own builtins are split by mode, not one agent doing everything: `build`/`plan` are `primary`, `general`/`explore` are `subagent`, and `general` "cannot launch more subagents" — [Source](https://v2.opencode.ai/docs/agents); ravan's `mode: all` + `subagent: * allow` makes it both entrypoint and unbounded delegator, a shape no builtin uses
- V2 canonical reviewer pins `model: anthropic/claude-sonnet-4-5#high` with `steps: 8` and full edit/shell deny — [Source](https://v2.opencode.ai/docs/agents); community elite packs go further with per-role models (orchestrator on flagship reasoning variant, explorer/librarian on cheaper tiers) and hidden council subagents (`hidden: true`, `execute: * allow`) — [Source](https://gist.github.com/SoloUnity/47a9cf7dcef9812a6aaee7e14c321300)
- Semgrep's elite pattern (Agentic Workflows / Multimodal, 2026) encodes security analysis as multi-step pipelines combining deterministic engines (Pro Engine taint tracing, Mandoline code slicer feeding agents exactly the context needed) with frontier models for exploitability reasoning — "8x more true positives while cutting noise by 50% compared to foundation models alone" — [Source](https://www.businesswire.com/news/home/20260319711078/en/Semgrep-Launches-Multimodal-Combining-AI-Reasoning-With-Rule-Based-Analysis-for-Detection-Triage-and-Remediation); ravan has the deterministic half (stdlib scripts) but no pipeline/slicer/decomposition — one agent, one context, unbounded steps
- Burp AI's elite pattern separates passive observation from active verification with explicit risk gating: passive scanner → queue → active scanner with per-point payload budgets (`Max Payloads per Point` 1–50, concurrent-scan caps, DANGEROUS level gated behind explicit permission) and `[AI Active]`-prefixed reporting — [Source](https://burp-ai-agent.six2dez.com/scanners/active); ravan collapses both roles into one agent whose only active-work control is a deny list plus prose
- Burp AI extension agents use "up to 8 tool calls" auto-chaining budgets, token-aware caps, dedup windows, and prompt-result caching to bound cost — [Source](https://burp-ai-agent.six2dez.com/); ravan has no steps budget, so a runaway recon loop has no backstop except context exhaustion
- V2 `hidden` "controls visibility, not security — use permissions to restrict behavior" — [Source](https://v2.opencode.ai/docs/agents); ravan uses zero hidden agents, so it cannot do the elite orchestrator→hidden-scout/reviewer fan-out that keeps noisy intermediate work out of the user's context
- Ravan's `question` usage is one line ("use `question` to resolve authorization ambiguity") — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md); elite authorization-gate design (its own skill's Step 0: owner / non-owner-responsible-disclosure / ambiguous→ask triage with `--i-am-authorized` enforcement in code) lives in the skill, not the agent — [local SKILL.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\skills\web-recon-passive\SKILL.md) — meaning code-review and hardening sessions (where the skill never loads) run with no authorization gate at all

### Inferences
- SEV-HIGH: no `model` pin means ravan's behavior (including its prized false-positive discipline, which is pure prompt prose) varies silently with whatever session model is selected; the deterministic-judgement claims are ungrounded without a pinned reasoning-tier model.
- SEV-HIGH: no `steps` budget means no cost/latency ceiling and no forced summarization; elite baseline is `steps: 8` for a reviewer, higher only for orchestrators.
- SEV-MEDIUM: single `mode: all` monolith vs elite team topology; fix is split into `ravan` (primary orchestrator, question-heavy, edit-ask) + hidden `ravan-scout` (read-only recon, steps-bounded) + hidden `ravan-reviewer` (deny edit/shell, code-review only).
- SEV-LOW: missing `color` is cosmetic but signals the agent was never finished to V2 display standards; one-line fix.
- SEV-MEDIUM: authorization gating belongs on the agent (all session types), not just inside one skill.

### Gaps
- No reliable public source found on Pangea or Protect AI agent internal architectures (modes/steps/models); they were named in the brief but no citable design details surfaced — treated as missing, not as confirmed parity or gap.
- Exact elite `steps` values for security agents (vs generic reviewers) not found; `8` is the only documented V2 reference number.

## 3. Missing Autonomy

### Takeaway
Ravan has no task decomposition, no background delegation pattern, no self-verification loop, and no plan-then-execute path — it is a single-pass advisor, while elite agents run bounded multi-step pipelines with verification stages.

### Cited Findings
- Ravan's system prompt contains no decomposition protocol, no background-subagent pattern, and no verification loop; its operating notes list only tool preferences and the ask/deny fallback — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md)
- V2 subagents run "in foreground or background child sessions" and the parent's `subagent` permission controls launch rights — [Source](https://v2.opencode.ai/docs/agents); ravan neither documents nor demonstrates background fan-out (e.g. DNS/TLS/headers/JS-bundle checks in parallel), even though its own skill enforces inter-request delays that make parallelization the obvious latency win — [local SKILL.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\skills\web-recon-passive\SKILL.md)
- V2 reserves `plan_enter`/`plan_exit` actions and ships a `plan` agent that "denies edits except OpenCode plan files" — [Source](https://v2.opencode.ai/docs/permissions); ravan has no plan-mode integration, so high-stakes remediation plans (CSP rollout, HSTS sequencing it rightly obsesses over) are drafted with the same edit-capable session that executes them — no plan-then-execute separation
- Semgrep's 2026 platform makes validation a first-class pipeline stage ("Detect → Validate → Drive code changes… Generate PRs that reference impact, context, and validation") with managed orchestration, retries, and cost tracking — [Source](https://app.semgrep.dev/products/semgrep-agentic-workflows); Burp AI's passive→active promotion loop auto-queues passive findings for active confirmation — [Source](https://burp-ai-agent.six2dez.com/scanners/active); ravan's "verification checklist" is a static text section the user runs by hand — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md)
- Semgrep Assistant's semi-autonomous triage (deterministic SAST → LLM false-positive filter at "95% alignment rate with users", memories of past triage decisions compounding to "up to 40% workload reduction after one week") — [Source](https://semgrep.dev/blog/2025/announcing-ai-noise-filtering-and-triage-memories) — is the elite template for autonomy-with-auditability; ravan keeps no memory, no triage history, no suppression list across runs
- The `general` builtin "handles research and multi-step work" but "cannot launch more subagents" (depth cap), and `explore` is read-only — [Source](https://v2.opencode.ai/docs/agents); ravan as primary could lawfully fan out to these today but its prompt never does, so available autonomy goes unused

### Inferences
- SEV-HIGH: no plan-then-execute for remediation guidance (HSTS/CSP/DNS changes it prescribes can break production; its own prompt admits `includeSubDomains` "breaks any subdomain without valid HTTPS") — plans with blast radius need a denied-edits planning pass first.
- SEV-HIGH: verification is delegated to the user (checklist prose) where elite agents close the loop mechanically (re-scan, re-request, diff evidence); every "verified" claim out of ravan is single-pass.
- SEV-MEDIUM: no background/parallel delegation pattern despite an embarrassingly parallel workload (DNS, TLS, headers, CT logs, bundle fetch are independent) and delay-enforced tooling.
- SEV-MEDIUM: no cross-run memory (suppressed false positives, target architecture verdicts) — repeat reviews of the same target redo all judgement calls from scratch.

### Gaps
- Could not confirm whether V2 exposes a programmatic retry/timeout/cost-tracking surface to agents (Semgrep's managed infra does); assumed absent from agent-authoring scope.

## 4. Unused OpenCode V2 Features

### Takeaway
Ravan uses exactly two V2 surfaces (markdown agent + skill with scripts/references) and leaves commands, MCP servers, project config, instructions, and agent display options entirely untouched — the `opencode.jsonc` is an empty schema stub.

### Cited Findings
- Project `opencode.jsonc` contains only `{"$schema": ...}` — no `default_agent`, `agents` overrides, `instructions`, `mcp`, `commands`, or shared `permissions` baseline — [local opencode.jsonc](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\opencode.jsonc)
- No `.opencode/commands/` directory exists (only `agents/` and `skills/`) — [local .opencode](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode); V2 commands turn prompt templates into slash commands with `agent`/`model` selection and `!`-backtick shell interpolation (e.g. a `/passive-review` command pinning the ravan agent + target args) — [Source](http://dev.opencode.ai/v2/docs/commands); the skill instead registers itself as a slash command (`opencode/slash: true`), which collides with rather than replaces project commands
- No MCP servers configured; V2 supports local (`type: local`, stdio command) and remote MCP tooling auto-available to the LLM under the same permission model (`<server>_<tool>` action resources) — [Source](https://github.com/fuxingloh/opencode/blob/main/packages/web/src/content/docs/mcp-servers.mdx); the Semgrep-skills precedent packages scanner capabilities (semgrep scan, rulesets, AST dump) as installable agent skills over MCP/CLI — [Source](https://github.com/semgrep/skills) — while ravan's deterministic tooling remains hand-rolled stdlib scripts with no MCP surface
- V2 `instructions` array exists in config schema but "parses and retains this field but does not resolve its entries into instruction sources… therefore do not reach the model yet"; ambient `AGENTS.md` discovery is the working channel — [Source](https://v2.opencode.ai/instructions); the repo has no `AGENTS.md`, so project-level conventions (report output dir, contact identity for User-Agent, request budget defaults) are re-negotiated every session
- Agent frontmatter uses none of `model`, `steps`, `color`, `hidden`, `disabled`, `request` — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md); additionally V2 per-agent `request` body overlays (the only temperature-shaped knob, e.g. `body: {temperature: 0.1}`) are "preserved but not yet applied to model requests" by the current session runner — [Source](https://v2.opencode.ai/docs/agents) — so even the available determinism lever is currently decorative
- Skill-side positives actually present (to avoid misreporting as gaps): `references/` ships all three cited files (`legal-and-scope.md`, `remediation-library.md`, `reporting-guide.md`) and `scripts/` ships the full toolchain (`recon.py`, `checks.py`, `cve.py`, `dnslib.py`, `webfetch.py`, both test/validation harnesses) — [local skill dir](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\skills\web-recon-passive)
- `ravan.md` (distribution copy) and `.opencode/agents/ravan.md` are manually kept "identical… same hash" — [local README.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\README.md); there is no sync check in config, hooks, or CI — drift is a matter of time, and V2 config `agents` merging ("later scalar values replace earlier") means a future global `ravan` entry would silently override one copy — [Source](https://v2.opencode.ai/docs/agents)

### Inferences
- SEV-MEDIUM: zero slash commands for the three core jobs (passive review, diff review, hardening plan) — every engagement starts from freeform prose instead of a pinned agent+model+template invocation.
- SEV-MEDIUM: zero MCP surface — no SBOM feed, no advisory-DB lookup, no Nuclei/ZAP bridge for the authorized-active tier; the skill's `--no-cve` offline fallback exists precisely because advisory correlation is bolted on rather than infrastructural.
- SEV-MEDIUM: empty `opencode.jsonc` — no shared permission baseline, no `default_agent`, no formatter/config pinning; the "minimal project config" is indistinguishable from an unconfigured one.
- SEV-LOW: no `AGENTS.md` for durable project conventions (currently the only working instruction channel since `instructions[]` is unresolved in V2).
- SEV-LOW: manual dual-copy sync of ravan.md with no enforcement; fix is single source + install script or a hash-check command.

### Gaps
- "Snapshots" and "policies" named in the brief do not appear as agent-authoring surfaces in the fetched V2 docs (only `plan_enter`/`plan_exit` built-in policy reservations); whether they exist under other names is unconfirmed — flagged as unverified, not as confirmed-missing.
- "Formatters" similarly unconfirmed as a V2 config surface; not claimed either way.

## 5. Determinism / Reproducibility Gaps

### Takeaway
Ravan's prompt claims it "works deterministically" while the architecture provides zero determinism controls: no pinned model, no reachable temperature knob in V2, no run log, no eval harness for the agent itself.

### Cited Findings
- Ravan's opening line asserts "You work deterministically and evidence-first" — [local ravan.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md); the README confirms V2-native status by the *absence* of legacy `temperature`/`permission`/`tools` keys — [local README.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\README.md) — i.e. determinism is claimed by prompt adjective, not mechanism
- No `model:` is pinned, so the agent inherits "the parent session's model when none is configured" and "selecting a primary agent by ID does not change that model" — [Source](https://v2.opencode.ai/docs/agents); identical prompts can route to different model families across sessions with no record of which one produced a given report
- The only per-agent temperature-shaped control (`request.body.temperature`) is explicitly non-functional: "the current V2 session runner preserves these overlays… but does not yet apply them" — [Source](https://v2.opencode.ai/docs/agents); legacy top-level `temperature` is banned in V2 agents — [Source](https://v2.opencode.ai/docs/agents); there is currently no working sampling control available to the agent author at all
- No `steps` bound (see §2), so run length — and hence evidence depth — is nondeterministic across runs even on the same model
- The repo's 42 offline unit tests cover the skill's *scripts* (`test_checks.py`, bundle-replay validation) — [local SKILL.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\skills\web-recon-passive\SKILL.md); nothing evaluates the *agent*: no golden-report fixtures, no false-positive regression prompts, no severity-calibration cases, no prompt-regression check that would catch drift between the two manually-synced ravan.md copies
- The skill emits machine-readable JSON facts + full request log per run (`<host>-<timestamp>.json` with "all facts and request log") — [local SKILL.md](D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\skills\web-recon-passive\SKILL.md); but the agent layer above it records no model identity, prompt version, or skill version alongside its verdicts, so a report cannot be reproduced or audited after the fact
- Elite contrast: Semgrep builds reproducibility into the platform (deterministic Pro Engine underneath the LLM, versioned pre-built workflows, managed infrastructure handling "orchestration, retries, and cost tracking at scale", credit-metered runs visible per job) — [Source](https://app.semgrep.dev/blog/2026/introducing-semgrep-agentic-workflows-automate-deep-vulnerability-hunting-at-scale); Burp AI preserves "auditable, reproducible prompt bundles" with request logging and trace-ID correlation — [Source](https://burp-ai-agent.six2dez.com/)

### Inferences
- SEV-HIGH: "deterministic" is the single most load-bearing word in the system prompt and it is currently unimplementable in V2 (no model pin + no temperature path) — the claim should be downgraded to "evidence-first, model-dependent" until both controls exist, or reports must stamp model/prompt/skill versions to make variance auditable.
- SEV-HIGH: no agent-level eval harness — the false-positive discipline (the project's crown jewel, with named traps like react-dom internals and `javascript:` blockers) is protected only by script unit tests; a prompt regression that reintroduces any of them would ship silently.
- SEV-MEDIUM: no run manifest (model id, agent hash, skill version, request log) attached to findings; fix is a mandatory report header block sourcing the skill's existing JSON log plus session metadata.
- SEV-LOW: timestamped output filenames (`<host>-<timestamp>`) already prevent accidental overwrite; keep, but add content-hash naming for dedup.

### Gaps
- Whether the provider/model-variant layer (the docs' recommended fallback for request settings) exposes temperature per model in the user's deployment was not investigated; a pinned variant (e.g. `#low`-temperature equivalent) may partially close this gap.
- No source found for agentic-coding eval-harness best practices specific to OpenCode V2 custom agents; general eval guidance would need a separate research pass.
