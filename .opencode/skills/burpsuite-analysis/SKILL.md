---
name: burpsuite-analysis
description: Use when analyzing Burp Suite scan results to extract findings, categorize vulnerabilities, and generate security reports.
---

# Burp Suite Analysis

## When to Use This Skill
- Extracting findings from a Burp Suite project file
- Categorizing vulnerabilities by type and severity
- Generating a structured security report from scan results
- Correlating findings across multiple scan results

## Workflow
1. Open the Burp Suite project file or export findings as XML/JSON
2. Parse the exported data to extract request/response pairs
3. Categorize findings by vulnerability type (XSS, SQLi, IDOR, etc.)
4. Assess severity: Critical, High, Medium, Low, Informational
5. Deduplicate findings that appear across multiple endpoints
6. Generate a report: executive summary, findings by severity, and remediation steps
7. Prioritize remediation based on exploitability and impact

## Rules
- Always verify findings manually before reporting — automated scans produce false positives
- Include the full request/response for each finding so it can be reproduced
- Categorize using CWE or OWASP classifications for consistency
- Don't ignore Informational findings — they often indicate misconfigurations
- Report findings in order of severity, not order of discovery
- Track remediation status for each finding
