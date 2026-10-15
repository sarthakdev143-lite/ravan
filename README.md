# ravan

An OpenCode agent for application-security and offensive-security work — passive assessment, secure code review, hardening guidance, and actionable reporting. V2-native (`mode: all`, `permissions` list, no legacy `temperature` / `permission` / `tools` keys).

Works as a primary session agent (like `build` / `plan`) and as a `@ravan` subagent.

## Layout

```text
ravan/
├── ravan.md                          # distribution copy — install this globally
├── .opencode/
│   ├── agents/ravan.md               # project-local agent (same content, auto-discovered)
│   └── skills/web-recon-passive/     # passive web-review skill (DNS, TLS, headers, JS, CVE)
├── docs/build-prompt.md              # original build prompt (dev history)
├── opencode.jsonc                    # minimal project config
├── LICENSE                           # MIT
└── README.md                         # this file
```

`ravan.md` and `.opencode/agents/ravan.md` are identical by design. Keep them in sync (same hash).

## Capabilities

- **Passive recon first:** DNS / SPF / DKIM / DMARC / CAA / DNSSEC / MTA-STS, cert-transparency, TLS chain, HTTP security headers, tech fingerprinting, public JS/CSS bundle analysis.
- **Architecture before severity:** states what the target's architecture makes impossible (e.g. static SPA → no SQLi/RCE/SSRF) instead of flagging noise.
- **Offensive methodology, planning-level:** intrusion lifecycle, OWASP Top 10 / ASVS / Testing Guide, MITRE ATT&CK, web classes (SQLi, XSS, CSRF, SSRF, IDOR, deserialization, auth/session, upload, traversal, logic abuse), rules-of-engagement scoping.
- **Tooling literacy without execution:** Burp, nmap, nuclei, sqlmap, Metasploit, ffuf — plans, drafts commands for an authorized operator, interprets output. Does not launch them (denied by policy).
- **Defensive:** CSP/HSTS/cookies/CORS/TLS, secure code review (JS/TS, Python, Go, Java, PHP, Ruby, .NET), SBOM / supply-chain / CVE gating, logging/IR basics, email-auth sequencing (monitor → quarantine → reject).
- **Reporting:** verbatim evidence + mechanism + target-terms impact + exact fix + verification checklist, plus a false-positive appendix.

## Safety model

- `shell: *` defaults to `ask`. Allowlisted: `git status/diff/log`, `grep`, `ls`, `cat`, `dig`, `nslookup`, `openssl s_client`, `curl -sSI`, `python* skills/*/scripts/*`, `npm audit/ls`.
- Denied: `rm -rf`, `mkfs`, `dd`, `nmap`, `nikto`, `sqlmap`, `hydra`, `metasploit`, `msfconsole`, `gobuster`, `ffuf`, `nuclei`. The deny block is intentional — active scanning belongs in a separately authorized engagement. The agent helps plan/scope/interpret instead.
- Authorization gate: passive review of public info is fine; probing / fuzzing / injecting / brute-forcing / exploiting requires confirmed ownership or written permission. Third parties are out of scope by default.

## Install

Requires OpenCode V2. See <https://opencode.ai/v2/docs/agents/>.

```powershell
# Global — available in every project (this is what puts `ravan` in Select agent)
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.config\opencode\agents" | Out-Null
Copy-Item -Path "ravan.md" -Destination "$env:USERPROFILE\.config\opencode\agents\ravan.md" -Force

# Project-local — auto-discovered when you open this repo (already present)
# .opencode/agents/ravan.md
# .opencode/skills/web-recon-passive/
```

```bash
# macOS / Linux equivalent
mkdir -p ~/.config/opencode/agents
cp ravan.md ~/.config/opencode/agents/ravan.md
```

Restart the TUI / reload the session. `ravan` appears in **Select agent** next to `build` and `plan`.

Optional — make it the default for this project in `opencode.jsonc`:

```jsonc
{
  "default_agent": "ravan",
}
```

## Use

```text
# as primary agent: select `ravan` in Select agent, then
do a passive security review of https://example.com
review this diff for auth bypass and IDOR
write a CSP rollout plan for this SPA

# as subagent from any other agent
@ravan review my current changes for injection and access-control flaws
```

The `web-recon-passive` skill auto-loads for external website reviews. Scripts run offline-capable on stdlib-only Python 3.8+:

```bash
python .opencode/skills/web-recon-passive/scripts/test_checks.py
```

## Verify

```bash
python .opencode/skills/web-recon-passive/scripts/test_checks.py  # 42 offline unit tests
```

Frontmatter checks: valid YAML, `description` present, `mode: all`, no `tools` / `permission` / `temperature` keys, `shell: * → ask` first with specific allows then denies last (last match wins).

## License

MIT — see `LICENSE`.
