# Tooling matrix — purpose, wrong choice, output reading

Plan, draft (for authorized operators), and interpret. Never execute
denied tooling. Invocation drafts belong in operator handoff, version-pinned.

| Tool | For | Wrong choice when | Output reading |
|---|---|---|---|
| nmap | host/port/service discovery (authorized) | passive-only scope, third parties | service/version rows → map to exposure, not vulns |
| Nuclei | fast automatable checks via YAML templates, severity/tag filters | host discovery, deep logic | template match = what the matcher proved; check severity + CVE refs |
| sqlmap | injection confirmation (authorized) | blind automation without scope | payload success vs WAF-blocked vs inconclusive |
| ffuf/gobuster | content discovery (authorized) | unauthenticated third-party enumeration | status/size clusters; 403 vs 200 vs 301 meaning |
| Burp Repeater/Intruder/Scanner/Collaborator | manual deep-dives, session/auth logic | bulk scanning | collaborator callbacks = real SSRF/OOB proof |
| ZAP | spider/ajax/baseline scans in CI/staging | production intrusive | baseline HTML → triage by confidence |
| Metasploit | module-selection reasoning (authorized labs) | anything without written scope | module rank + check-code result, not hype |
| hydra | auth-strength reasoning (authorized, rate-aware) | lockout-risky targets | lockout warnings first; rate math in plan |
| Nikto | quick misconfig sweep (authorized) | noisy production | high-FP baseline, verify each |
| Semgrep | deterministic SAST, taint source→sink | unscoped autofix | rule ID + path + dataflow; re-rank by reachability |
| CodeQL | deep semantic queries | quick triage | query result + path reconstruction |
| BloodHound | AD attack paths (authorized) | no AD scope | shortest-path to DA, cut edges |
| Prowler/ScoutSuite/Cloudsplaining | cloud misconfig review | live mutation | findings → IAM/policy diffs |
| Amass/subfinder/httpx | asset enumeration (authorized scope) | passive-only engagements | alive-set vs resolved-set discipline |
| dalfox | XSS verification (authorized) | blind runs | reflected-context classification |

SAST-output rule: a Semgrep/CodeQL taint path is the closest complement
to manual review — treat tool paths as candidate taint, confirm the source
is attacker-reachable before rating.
