# Ravan Offensive-Security Coverage Gaps

Ground truth: `D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\agents\ravan.md` (296 lines) and `D:\Sarthak\Coding\My Codes\Cybersecurity\ravan\.opencode\skills\web-recon-passive\SKILL.md` (205 lines), read in full October 2026. Ravan is explicitly a passive-only assessment agent with a deny-list for active scanners; this audit judges it as an offensive-security *planner/reasoner*, which is its own stated scope ("Full intrusion lifecycle", "Frameworks: OWASP Top 10, OWASP ASVS / Testing Guide, MITRE ATT&CK").

## OWASP Top 10 2021/2025, OWASP API Top 10, OWASP LLM Top 10, MITRE ATT&CK coverage

### Takeaway
Ravan names only the generic "OWASP Top 10" and omits the 2025 edition's new categories, the entire API Top 10 and LLM Top 10, and reduces ATT&CK to a name-drop with no tactic/technique literacy.

### Cited Findings
- OWASP Top 10 2021 has 10 categories: A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable and Outdated Components, A07 Identification and Authentication Failures, A08 Software and Data Integrity Failures, A09 Security Logging and Monitoring Failures, A10 SSRF — [Source](https://owasp.org/Top10/2021/)
- OWASP Top 10 2025 (release candidate, announced Nov 6 2025 at Global AppSec) reorders to: A01 Broken Access Control, A02 Security Misconfiguration (up from #5), A03 Software Supply Chain Failures (new, replaces Vulnerable & Outdated Components), A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging & Alerting Failures, A10 Mishandling of Exceptional Conditions (new); SSRF folded into A01 — [Source](https://top10.owasp.org/2025/0x00_2025-Introduction); [Source](https://www.fastly.com/blog/new-2025-owasp-top-10-list-what-changed-what-you-need-to-know)
- OWASP API Security Top 10 2023: API1 BOLA, API2 Broken Authentication, API3 Broken Object Property Level Authorization, API4 Unrestricted Resource Consumption, API5 Broken Function Level Authorization, API6 Unrestricted Access to Sensitive Business Flows, API7 SSRF, API8 Security Misconfiguration, API9 Improper Inventory Management, API10 Unsafe Consumption of APIs; BOLA is #1 and figures in ~40% of API attacks — [Source](https://owasp.org/API-Security/editions/2023/en/0x11-t10); [Source](https://salt.security/blog/owasp-api-security-top-10-explained)
- OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption — [Source](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- MITRE ATT&CK Enterprise (v18, Oct 2025) has 14 tactics, 216 techniques, 475 sub-techniques, including Reconnaissance (TA0043), Credential Access (TA0006), Defense Impairment/Evasion, Privilege Escalation, Lateral Movement, Exfiltration, Impact; recent additions include AI-Enabled Exfiltration (T1700), Poisoned Pipeline Execution, Container CLI/API — [Source](https://attack.mitre.org/tactics/enterprise/); [Source](https://attack.mitre.org/resources/updates/updates-october-2025/)
- Cloud instance metadata access is a tracked ATT&CK sub-technique: Unsecured Credentials: Cloud Instance Metadata API (T1552.005), reached via SSRF against IMDS endpoints — [Source](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/cross-platform/credential_access_web_server_cloud_imds_ssrf_request)
- Ravan's prompt mentions only "OWASP Top 10, OWASP ASVS / Testing Guide, MITRE ATT&CK" with no edition, no API/LLM lists, no tactic or technique IDs, and no mapping discipline beyond "where it aids prioritization, not as decoration" — ground truth from `ravan.md` lines 153–159
- Ravan's vuln-class list covers only: SQLi, NoSQLi, command injection, XSS (3 flavors), CSRF, SSRF, IDOR/broken access control, deserialization, auth/session, file-upload, path traversal, business-logic abuse — ground truth from `ravan.md` lines 160–164

### Inferences
- Every 2025-delta category is a blind spot: A03 Software Supply Chain Failures (CI/CD, build integrity), A10 Mishandling of Exceptional Conditions (fail-open, error-state abuse), and the demotion/reframing of SSRF into access control have no prompt presence. Fix: add an explicit edition-pinned mapping table (2021 + 2025 RC/final) to the agent prompt with CWE crosswalks.
- API Top 10 is entirely absent despite APIs being the dominant attack surface in 2026: no BOLA/BFLA/BOPLA reasoning, no mass-assignment, no excessive data exposure, no rate-limit/resource-consumption analysis, no shadow-version inventory thinking. Fix: add an API-security section to the prompt keyed to API1–API10 with plan-only test checklists.
- LLM Top 10 is entirely absent: no prompt-injection, system-prompt leakage, excessive agency, RAG/vector-DB, or unbounded-consumption reasoning, even though Ravan itself is an LLM agent assessing LLM-era apps. Fix: add an LLM-app assessment annex (LLM01–LLM10, planning-level only).
- ATT&CK is decorative: no tactic coverage (Reconnaissance through Impact), no technique IDs, no mapping of passive findings to follow-on active techniques an authorized operator should test (e.g., T1595 Active Scanning, T1190 Exploit Public-Facing Application, T1552.005 metadata API). Fix: require ATT&CK tactic+technique tagging on every finding and on every planned next step.

### Gaps
- Whether OWASP Top 10 2025 RC became final by October 2026 could not be verified from fetched sources (only RC1 coverage found); the report writer should pin the final list before writing prompt text.
- No reliable source found quantifying exactly how many ATT&CK techniques a "best-in-class agent" must know; noted as gap rather than invented.

## Vuln classes lacking depth

### Takeaway
Ravan's 12-class web list is a 2017-era core; it has zero prompt literacy for JWT/OAuth/OIDC, GraphQL, WebSockets, race conditions, SSTI, XXE, prototype pollution, cloud/SSRF-metadata chains, Kubernetes, mobile, and binary — all of which PortSwigger treats as first-class test areas in 2026.

### Cited Findings
- PortSwigger Web Security Academy's 2026 topic list includes dedicated tracks for JWT attacks, OAuth authentication, GraphQL API vulnerabilities, WebSockets, race conditions, SSTI, XXE, prototype pollution, NoSQL injection, API testing, web cache poisoning/deception, and Web LLM attacks — [Source](https://portswigger.net/web-security)
- JWT attacks hinge on alg confusion (none-algorithm, jku/x5u header injection), weak secrets, and kid manipulation — [Source](https://portswigger.net/web-security/jwt)
- OAuth testing requires multi-parameter combination analysis (redirect_uri + response_mode + state), not single-parameter probing — [Source](https://portswigger.net/web-security/oauth)
- Race-condition methodology is "predict, probe, prove": map multi-step sequences, predict collisions (limit overruns, multi-endpoint state machines per the 2023 "Smashing the state machine" research), then prove with parallelized requests — [Source](https://portswigger.net/web-security/race-conditions)
- APIs are described as "the most exploited attack surface in 2026" with JWT, OAuth-flow, and GraphQL abuse (introspection, nested-query DoS, field-level authz) as the leading vectors — [Source](https://hivesecurity.gitlab.io/blog/api-security-jwt-oauth-graphql-attacks)
- SSRF in cloud environments escalates to credential theft via metadata services (AWS IMDS, GCP metadata with Metadata-Flavor header, Azure IMDS) and onward to Kubernetes API access using pod service-account tokens — [Source](https://www.appsecure.security/blog/ssrf-cloud-environments); [Source](https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.html); [Source](https://www.resecurity.com/blog/article/ssrf-to-aws-metadata-exposure-how-attackers-steal-cloud-credentials)
- Ravan's prompt has no mention of JWT, OAuth, OIDC, SAML, GraphQL, WebSocket, race condition, SSTI, XXE, prototype pollution, XXE, cloud metadata, IMDS, Kubernetes, container, mobile, binary, firmware, or deserialization beyond one word — verified by full read of `ravan.md` and `SKILL.md`
- Ravan's skill is HTTP/DNS/TLS/JS-bundle only and states CMS targets "will under-report; say so" — ground truth from `SKILL.md` lines 36–44, 98–101

### Inferences
- Each missing class is a finding with impact: auth-token flaws (JWT/OAuth) are the highest-severity web findings after access control and Ravan cannot plan their review; GraphQL/WebSocket endpoints are invisible to its bundle-grep model; race conditions and business-logic abuse (only named, never methodologized) are where scanners fail and agents must add value. Fix: add per-class planning blocks (preconditions, detection-at-planning-level, safe verification steps for an authorized operator, Burp/ZAP workflow pointers) for at minimum: JWT, OAuth/OIDC, GraphQL, WebSockets, SSTI, XXE, prototype pollution, race conditions, HTTP request smuggling, cache poisoning, file-upload polyglots, NoSQL/LDAP/XPath injection, XXE-adjacent (already folded into A05), cloud-metadata SSRF chains, K8s RBAC/service-account review, mobile (MASVS) triage, and binary/taint basics.
- The skill's honest "will under-report" caveat needs a prompt-level counterpart: a coverage matrix (covered / partial / absent-per-class) in every report's limitations section. Fix: mandate the matrix in the output-style section.
- XXE deserves explicit resurrection: folded into A05:2021 it is easy to forget, yet file-upload/SVG/SAML/Office parsers keep it alive. Fix: name it explicitly in the injection list.

### Gaps
- Mobile (OWASP MASVS/MSTG) and binary/reverse-engineering depth for agents could not be sourced to a citable agent-benchmark within budget; flagged as absent from Ravan without prescribing a specific framework edition.

## Missing methodology: threat modeling, attack trees, kill chain, purple-team, RoE

### Takeaway
Ravan's "methodology" is a five-word lifecycle plus a one-line RoE mention; it lacks every planning artifact that distinguishes an engagement from a scan: threat modeling, attack trees, kill-chain/purple-team mapping, and real scope negotiation.

### Cited Findings
- PTES defines seven phases: Pre-Engagement Interactions, Intelligence Gathering, Threat Modeling, Vulnerability Analysis, Exploitation, Post-Exploitation, Reporting — [Source](https://kirkpatrickprice.com/blog/stages-of-penetration-testing-according-to-ptes)
- Pre-engagement/RoE must fix scope (in/out assets), timing windows, forbidden techniques (DoS, social engineering, physical), emergency contacts, data handling, and legal authorization; nothing outside RoE without fresh approval — [Source](https://deepstrike.io/blog/penetration-testing-methodology); [Source](https://blog.securelayer7.net/penetration-testing-rules-of-engagement)
- STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation) enumerates threats per component/trust boundary; attack trees decompose one high-value goal into AND/OR paths; PASTA is a 7-stage risk-centric process tying threats to business impact; the standard combo is STRIDE for breadth + attack trees for depth + CVSS/risk-matrix for priority (DREAD deprecated) — [Source](https://strobes.co/blog/threat-modeling-explained-stride); [Source](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html); [Source](https://threat-modeling.com/pasta-threat-modeling)
- OWASP A04:2021 Insecure Design explicitly calls for "more threat modeling, secure design patterns and principles, and reference architectures" and notes insecure design cannot be fixed by perfect implementation — [Source](https://owasp.org/Top10/2021/A04_2021-Insecure_Design/index.html)
- Best-in-class 2026 agents run planner-executor or swarm architectures (planner picks strategy, recon/exploit/reporter agents execute), chain tools toward goals with ReAct loops, and structure work around explicit methodologies rather than single-shot scans — [Source](https://appsecsanta.com/research/ai-pentesting-agents-2026); [Source](https://matproof.com/blog/ai-penetration-testing-guide); [Source](https://www.synack.com/learning-center/what-is-ai-penetration-testing-complete-guide)
- Ravan's methodology section is: one lifecycle sentence (recon → scanning → exploitation → post-exploitation → reporting), one frameworks line, one 12-class vuln list, one RoE sentence fragment, one tooling line — ground truth from `ravan.md` lines 153–171; no STRIDE, PASTA, attack tree, kill chain, purple team, DREAD/CVSS-scoring, or scope-negotiation playbook anywhere in either file

### Inferences
- Missing pre-engagement machinery is the most operationally costly gap: Ravan can "help write" RoE but has no template, no scope-negotiation questions, no authorization-tier ladder (passive / active-safe / intrusive), no emergency/stop-condition language. Fix: add an RoE drafting template + scope-negotiation question bank to the prompt or a new skill.
- Missing threat-modeling machinery means findings arrive unprioritized by design: no STRIDE-per-component pass, no attack tree for the crown-jewel goal, no kill-chain mapping of where the assessed posture breaks the chain. Fix: require a threat-model section (assets, trust boundaries, STRIDE-per-boundary, 1–2 attack trees for top goals) before findings in every report.
- Missing purple-team/active-test planning means the handoff to authorized testing is vague: no test-plan-per-finding (objective, technique, tool, success criterion, rollback), no явно staged validation backlog. Fix: mandate a "validation backlog" appendix mapping each gated/untestable claim to an authorized-operator procedure.
- Ravan's lifecycle omits pre-engagement and threat modeling phases that PTES puts first; fix by adopting PTES phase names verbatim so reports align with PCI DSS 4.0 methodology expectations.

### Gaps
- Purple-team/detection-mapping specifics (e.g., required mapping to ATT&CK mitigations/detections) were not sourced within budget; noted as direction, not prescription.

## Payload reasoning without weaponizing

### Takeaway
Ravan's safety rule ("detection string, safe header check") is the right instinct but is a single sentence with no payload-reasoning curriculum behind it; elite practice pairs Nuclei-template literacy and Burp/ZAP workflow planning with inert proofs.

### Cited Findings
- Nuclei separates engine (fast Go scanner for HTTP/DNS/TCP/etc.) from detection logic (plain-YAML templates, one check per template, community packs for CVEs/misconfigs/exposures); operators select by tags/severity/workflows and write custom templates for business-logic probes — [Source](https://tech-insider.org/nuclei-vulnerability-scanner-setup-2026); [Source](https://github.com/projectdiscovery/nuclei-templates); [Source](https://www.bugcrowd.com/blog/the-ultimate-beginners-guide-to-nuclei)
- Nuclei does not discover hosts (needs a live list) and complements rather than replaces manual Burp/ZAP deep-dives and pre-deployment SAST (Semgrep) / IaC scanning (Checkov) — [Source](https://trickest.com/tools/nuclei); [Source](https://tech-insider.org/nuclei-vulnerability-scanner-setup-2026)
- XBOW-style 2026 agents carry out simulated attacks with safety controls (e.g., no lateral movement), each agent targeting one outcome (file read, RCE) with standard tools plus LLM reasoning — [Source](https://xbow.com/blog/what-is-ai-pentesting)
- Ravan's rule 4 permits describing vuln classes + fixes and offering "defensive proof-of-concept logic (detection string, safe header check)" while forbidding tailored payloads without authorization — ground truth from `ravan.md` lines 210–214

### Inferences
- The rule is correct but content-free: no examples of what a safe PoC is per class (e.g., `{{7*7}}`-evaluation-neutral math check reasoning vs. exfiltration; time-delay-neutral logic; header-reflection observations), no Nuclei-template literacy (read a template's requests+matchers, explain what a match proves, draft template *sketches* for authorized operators), no Burp Repeater/Intruder/Collaborator or ZAP workflow planning. Fix: add a "safe verification catalog" — per-class inert observables + the Nuclei template tags that cover them + the Burp/ZAP module to use — all explicitly non-weaponized.
- Missing guardrail granularity: "unless authorization is confirmed" is binary; best practice tiers it (describe → inert detection → authorized-operator command draft → never: credentials replay, live transactions, lateral movement). Fix: encode the tier ladder in behavioral rules.
- Missing over-reliance control: 2026 guidance warns agentic pentest reports need human sign-off for PCI DSS/SOC 2 assessors — Ravan should state its outputs are machine-assisted drafts requiring qualified-tester attestation. Fix: add a compliance-attestation disclaimer line.

### Gaps
- No citable standard found for the exact boundary text between "detection string" and "working exploit" for agents; Ravan's current line is reasonable but unbenchmarked — flagged, not rewritten.

## Absent tooling literacy

### Takeaway
Ravan names 6 tools in one line and deny-lists their execution, but a planning agent's value is precisely in drafting commands and reading output — and for BloodHound, Cloudsplaining/Prowler, Semgrep/CodeQL, ZAP/nikto, and post-exploitation tooling it provides neither.

### Cited Findings
- Ravan's tooling line: "Burp Suite, nmap, nuclei, sqlmap, Metasploit, ffuf — what each is for, when it is the wrong choice, and how to read its output. Help plan, draft commands for an authorized operator to run, and interpret results" — ground truth from `ravan.md` lines 168–171
- Ravan's deny block covers nmap, nikto, sqlmap, hydra, metasploit/msfconsole, gobuster, ffuf, nuclei — ground truth from `ravan.md` lines 104–129
- Standard 2026 practice layers tools: Nuclei for the fast automatable layer, OpenVAS/Greenbone for infra, Burp/ZAP for manual deep-dives, Semgrep/Checkov pre-deploy, with scheduled Nuclei + SARIF-to-Security-tab automation — [Source](https://tech-insider.org/nuclei-vulnerability-scanner-setup-2026)
- Semgrep is the AI-assisted SAST/SCA/secrets platform pairing rules with AI reasoning for detection, triage, and remediation — [Source](https://semgrep.dev)
- Cloud/K8s/AD review has its own mandatory toolkit (BloodHound for AD attack paths, Prowler/Cloudsplaining for cloud misconfig, kube-bench/kubectl-RBAC review for clusters), documented in pentest cloud/K8s/IAM scope practice — [Source](https://appsecco.com/product-security-testing/cloud-k8s-iam)
- Ravan's prompt and skill name none of: ZAP, nikto (denied but unnamed in literacy line), gobuster, hydra, BloodHound, Prowler, Cloudsplaining, ScoutSuite, Semgrep, CodeQL, Checkov, OpenVAS/Greenbone, Amass/subfinder, httpx, dalfox, sqlmap beyond the name, or any output-reading rubric — verified by full read of both files

### Inferences
- Six named tools with zero depth (no when-to-use matrix, no example authorized-operator commands, no output-reading rubric, no false-positive notes per tool) is literacy theater. Fix: add a tooling matrix (tool → purpose → wrong-choice conditions → minimal authorized-operator invocation pattern → how to read/quality-check output) covering at minimum: nmap, Nuclei (+template tags/severity filters), sqlmap, ffuf/gobuster, Burp (Repeater/Intruder/Scanner/Collaborator), ZAP (spider/ajax/baseline), Metasploit (module-selection reasoning only), hydra (rate/lockout warnings), Nikto, Semgrep, CodeQL, BloodHound, Prowler, Cloudsplaining/ScoutSuite, Amass/subfinder, httpx, dalfox.
- SAST-output reading (Semgrep/CodeQL taint source→sink) is Ravan's closest missing complement to its code-review claim ("trace taint from source to sink" is asserted at `ravan.md` line 180 with no tool grounding). Fix: add Semgrep/CodeQL output-interpretation guidance tied to that claim.
- Cloud/AD tooling absence compounds the vuln-class gap: without BloodHound/Prowler literacy Ravan cannot plan AD or cloud reviews at all. Fix: add cloud/K8s/AD planning annex or explicitly scope them out in limitations (honest scoping beats silent ignorance).

### Gaps
- Exact invocation syntax for each tool was deliberately not collected (would shade into weaponization-adjacent detail and version-drift); the finding is about literacy structure, and command drafts belong in the prompt fix, version-pinned at write time.
