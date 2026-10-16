# ravan

An OpenCode security team for application-security and offensive-security
work — passive assessment, secure code review, hardening guidance, and
evidence-first reporting. V2-native (ordered `permissions`, no legacy
`temperature` / `permission` / `tools` keys).

Ravan runs as a primary session agent and as `@ravan`, leading a
least-privilege team of hidden subagents.

## Layout

```text
ravan/
├── ravan.md                          # distribution copy — install globally
├── .opencode/
│   ├── agents/
│   │   ├── ravan.md                  # orchestrator (mode: all, steps: 24)
│   │   ├── ravan-recon.md            # hidden passive-recon runner
│   │   ├── ravan-reviewer.md         # hidden read-only code reviewer
│   │   └── ravan-reporter.md         # hidden report renderer
│   ├── commands/                     # /assess /threat-model /review
│   │                                 # /harden /retest /roe
│   ├── skills/web-recon-passive/     # passive web-review skill
│   │   ├── scripts/                  # recon, checks, cve, enrich,
│   │   │                           # depwatch (OSV), diff, tests
│   │   └── references/               # legal, reporting, remediation,
│   │                                 # hardening-matrix, review-playbook,
│   │                                 # modern-surfaces, scoring-rubric,
│   │                                 # report-template, detect-respond,
│   │                                 # tooling-matrix, roe-template,
│   │                                 # recon-checklist
│   └── security/                     # findings ledger, suppressions,
│                                     # target profile (file memory)
├── AGENTS.md                         # auto-loaded project conventions
├── opencode.jsonc                    # shared perms + MCP + instructions
├── docs/build-prompt.md              # original build prompt (history)
├── LICENSE                           # MIT
└── README.md                         # this file
```

`ravan.md` and `.opencode/agents/ravan.md` are identical by design. Keep
them in sync (same hash).

## Capabilities

- **Agent team, not a monolith:** orchestrator fans out to hidden
  recon / reviewer / reporter subagents with bounded steps and
  deny-by-default policies.
- **Passive recon first:** DNS / SPF / DKIM / DMARC / CAA / DNSSEC /
  MTA-STS, CT logs (`crt.sh` guidance), TLS chain, headers, tech
  fingerprinting, JS/CSS bundle analysis with vendor-aware FP filtering.
- **Architecture before severity:** states what the target makes
  impossible (static SPA → no SQLi/RCE/SSRF) instead of flagging noise.
- **Modern surfaces:** OWASP 2025 delta (supply chain, exceptional
  conditions), API Top 10 (BOLA/BFLA/BOPLA), LLM Top 10, ATT&CK tactic +
  technique tagging, JWT/OAuth/GraphQL/WebSocket/SSTI/XXE/race/cloud-chain
  planning blocks.
- **Scored findings:** every finding carries severity + CVSS + KEV + EPSS
  + confidence + `exploitable`/`gated` verdict (`scripts/enrich.py`
  enriches keylessly, cached, offline-safe).
- **Memory:** append-only finding ledger, suppressions list, versioned
  per-target profile, baseline diffing (`scripts/diff.py`), `/retest`
  verification loops, OSV dependency watch (`scripts/depwatch.py`).
- **Defensive depth:** per-stack hardening matrix, per-language
  source→sink review playbook, IaC/container/CI-CD checklists,
  detection rules + IR runbooks, email-auth sequencing
  (monitor → quarantine → reject).
- **Reports that fund fixes:** enforced template (scope → exec summary →
  attack chain → findings → done-well → roadmap → verification → retest →
  disclosure → manifest → appendices incl. rejected positives).

## Safety model

- Shell `ask` by default; allowlisted recon/git/npm/python-scripts only.
- Denied: destructive primitives, scanner/brute-forcer classes (Unix +
  Windows LOLBins: `certutil`, `bitsadmin`, Mimikatz patterns).
- Secrets unreadable by policy (`*.env`, `*.pem`, `*.key` denied).
- Authorization gate every session via `question`; third parties out of
  scope by default; tiered proof (describe → inert observable → operator
  draft → never). Active work is planned/scoped/interpreted, never
  launched. Outputs are machine-assisted drafts needing qualified-tester
  attestation for compliance use.

## Install

Requires OpenCode V2. See <https://opencode.ai/v2/docs/agents/>.

```powershell
# Global — available in every project (puts `ravan` in Select agent)
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.config\opencode\agents" | Out-Null
Copy-Item -Path "ravan.md" -Destination "$env:USERPROFILE\.config\opencode\agents\ravan.md" -Force
```

```bash
# macOS / Linux equivalent
mkdir -p ~/.config/opencode/agents
cp ravan.md ~/.config/opencode/agents/ravan.md
```

Restart the TUI / reload the session. `ravan` appears in **Select agent**
next to `build` and `plan`. Project-local files work automatically when
you open this repo.

## Use

```text
/assess example.com        # intake first — no scan without it
/threat-model example.com  # assets, STRIDE, attack trees
/review                    # diff review via @ravan-reviewer
/harden CSP                # staged plan with blast-radius warnings
/retest RVN-001            # verify one finding, update ledger
/roe example.com           # draft Rules of Engagement
```

Or plain language: `do a passive review of https://example.com`,
`@ravan review my changes for IDOR`.

## Verify

```bash
python .opencode/skills/web-recon-passive/scripts/test_checks.py
python .opencode/skills/web-recon-passive/scripts/enrich.py --selftest
```

46 offline unit tests + enrich selftest. New `checks.py` patterns require
new fixtures proving they do not fire on react-dom.

## License

MIT — see `LICENSE`.
