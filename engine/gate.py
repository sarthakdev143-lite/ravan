#!/usr/bin/env python3
"""
gate.py — Ravan completion gate. Merged from opencode-pentester.

The agent NEVER decides "done" by its own judgment.
Completeness is a database fact, not a belief.

Gate checks:
  1. All open leads are closed (leads.jsonl)
  2. All findings have a verdict (findings.jsonl)
  3. All findings have evidence
  4. The report exists for the target
  5. No findings with status "open" and no verdict

Usage:
    python3 engine/gate.py [--target example.com] [--json]
    python3 engine/gate.py --phase recon
    python3 engine/gate.py --push   # print persistence directive if gate fails

Exit codes:
    0 = gate PASS (safe to report/complete)
    2 = gate FAIL (keep working — pending items listed)
"""

import argparse
import json
import os
import sys

_OK   = "[+]" if os.name == "nt" else "✔"
_MISS = "[!]" if os.name == "nt" else "✘"

LEDGER_PATH = os.path.join(".opencode", "security", "findings.jsonl")
LEADS_PATH = os.path.join(".opencode", "security", "leads.jsonl")


def _load_findings(target: str | None = None) -> list[dict]:
    if not os.path.exists(LEDGER_PATH):
        return []
    findings = []
    with open(LEDGER_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    continue
                schema = obj.get("schema", "")
                if schema in ("ravan-findings-v1", "ravan-verification-v1",
                              "ravan-scout-v1", "ravan-leads-v1"):
                    continue
                if target and obj.get("target", "").lower() != target.lower():
                    continue
                findings.append(obj)
            except json.JSONDecodeError:
                pass
    return findings


def _load_leads(target: str | None = None) -> list[dict]:
    if not os.path.exists(LEADS_PATH):
        return []
    leads = []
    with open(LEADS_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    continue
                schema = obj.get("schema")
                if schema == "ravan-leads-v1":
                    continue
                if target and obj.get("target", "").lower() != target.lower():
                    continue
                leads.append(obj)
            except json.JSONDecodeError:
                pass
    return leads


def _report_exists(target: str | None) -> bool:
    if not target:
        return os.path.exists("reports")
    report_dir = os.path.join("reports", target)
    return os.path.exists(report_dir) and any(
        f.endswith(".md") or f.endswith(".json")
        for f in os.listdir(report_dir)
    ) if os.path.isdir(report_dir) else False


def evaluate(target: str | None = None) -> dict:
    findings = _load_findings(target)
    leads = _load_leads(target)

    pending = []
    checks = {}

    # Check 1: Open leads
    open_leads = [l for l in leads if l.get("status") == "open"]
    checks["leads_exhausted"] = len(open_leads) == 0
    if open_leads:
        pending.append({
            "check": "leads_exhausted",
            "message": f"{len(open_leads)} open leads remain",
            "action": "python3 engine/leads.py list --open -> explore or close --reason each",
            "leads": [{"id": l.get("id"), "value": l.get("value"), "why": l.get("why")} for l in open_leads[:5]],
        })

    # Check 2: All findings have a verdict
    no_verdict = [f for f in findings if not f.get("verdict")]
    checks["all_findings_verdicted"] = len(no_verdict) == 0
    if no_verdict:
        pending.append({
            "check": "all_findings_verdicted",
            "message": f"{len(no_verdict)} findings lack verdict (exploitable/gated)",
            "action": "python3 engine/ledger_append.py --verification <id> --verdict ...",
            "findings": [f.get("id") for f in no_verdict[:5]],
        })

    # Check 3: All findings have evidence
    no_evidence = [f for f in findings if not f.get("evidence_ref") and not f.get("evidence")]
    checks["all_findings_have_evidence"] = len(no_evidence) == 0
    if no_evidence:
        pending.append({
            "check": "all_findings_have_evidence",
            "message": f"{len(no_evidence)} findings have no evidence reference",
            "action": "Re-run the check with --out to generate evidence, then update evidence_ref",
            "findings": [f.get("id") for f in no_evidence[:5]],
        })

    # Check 4: No findings stuck at open with no confidence
    unconfident = [f for f in findings if f.get("status") == "open" and not f.get("confidence")]
    checks["all_open_have_confidence"] = len(unconfident) == 0
    if unconfident:
        pending.append({
            "check": "all_open_have_confidence",
            "message": f"{len(unconfident)} open findings have no confidence level",
            "action": "Review and set confidence: high/medium/low for each",
            "findings": [f.get("id") for f in unconfident[:5]],
        })

    # Check 5: Report exists
    report_ok = _report_exists(target)
    checks["report_generated"] = report_ok
    if not report_ok:
        pending.append({
            "check": "report_generated",
            "message": f"No report found for target {target!r}",
            "action": f"Delegate to @ravan-reporter to generate the report",
        })

    gate_pass = all(checks.values())

    return {
        "target": target or "all",
        "findings_count": len(findings),
        "leads_count": len(leads),
        "checks": checks,
        "pending": pending,
        "gate": "PASS" if gate_pass else "FAIL",
        "complete": gate_pass,
    }


def format_push_directive(result: dict) -> str:
    """Format a persistence directive when the gate fails."""
    lines = [
        "=" * 60,
        "RAVAN PERSISTENCE DIRECTIVE",
        "Budget exhausted does NOT mean done. Keep working.",
        "=" * 60,
        "",
        f"Gate: {result['gate']} | Findings: {result['findings_count']} | Leads: {result['leads_count']}",
        "",
        "Pending mandatory items:",
    ]
    for item in result["pending"]:
        lines.append(f"  {_MISS} [{item['check']}] {item['message']}")
        lines.append(f"    -> {item['action']}")
    lines.extend([
        "",
        "New angles to try:",
        "  - Different subdomains / vhosts",
        "  - API endpoints not yet tested",
        "  - Error pages / edge cases",
        "  - Different HTTP methods on known endpoints",
        "  - Header injection / cache poisoning vectors",
        "  - Dependency CVEs not yet verified",
        "",
        "Run: python3 engine/leads.py list --open",
        "     python3 engine/gate.py [--target TARGET]",
        "=" * 60,
    ])
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description="Ravan completion gate — never stop until done")
    p.add_argument("--target", help="Filter to this target hostname")
    p.add_argument("--json", action="store_true", dest="as_json")
    p.add_argument("--push", action="store_true",
                   help="Print persistence directive if gate fails")
    args = p.parse_args()

    result = evaluate(args.target)

    if args.as_json:
        print(json.dumps(result, indent=2))
    elif args.push and not result["complete"]:
        print(format_push_directive(result))
    else:
        print(f"Gate: {result['gate']}")
        print(f"Findings: {result['findings_count']} | Leads: {result['leads_count']}")
        for check, ok in result["checks"].items():
            icon = _OK if ok else _MISS
            print(f"  {icon} {check}")
        if result["pending"]:
            print("\nPending (KEEP WORKING):")
            for item in result["pending"]:
                print(f"  {_MISS} {item['message']}")
                print(f"    -> {item['action']}")

    return 0 if result["complete"] else 2


if __name__ == "__main__":
    sys.exit(main())
