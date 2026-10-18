#!/usr/bin/env python3
"""
leads.py — Discovered-but-unexplored pathway ledger. Merged from opencode-pentester.

Nothing discovered is ever abandoned. Every vhost, endpoint, parameter,
credential, or CVE that is not tested to exhaustion RIGHT NOW becomes a lead.
The completion gate blocks "done" while any lead is open.

Usage:
    python3 engine/leads.py add --type vhost --value staging.example.com --source nmap --why "500 on /login"
    python3 engine/leads.py list [--open] [--target example.com]
    python3 engine/leads.py explore <id> "tested → clean"
    python3 engine/leads.py close <id> --reason dead
    python3 engine/leads.py summary [--target example.com]

Exit codes: 0 = success, 1 = error, 3 = open leads exist (for gate integration)
"""

import argparse
import datetime
import json
import os
import sys
import uuid

_OK   = "[+]" if os.name == "nt" else "✔"
_WARN = "[!]" if os.name == "nt" else "⚠"

LEADS_PATH = os.path.join(".opencode", "security", "leads.jsonl")
VALID_TYPES = {"vhost", "endpoint", "parameter", "credential", "cve", "service", "file", "config", "other"}
VALID_REASONS = {"explored", "false-positive", "dead", "out-of-scope", "duplicate"}
VALID_STATUSES = {"open", "explored", "closed"}


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
                lead = json.loads(line)
                if not isinstance(lead, dict) or lead.get("schema") == "ravan-leads-v1":
                    continue
                if target and lead.get("target", "").lower() != target.lower():
                    continue
                leads.append(lead)
            except json.JSONDecodeError:
                pass
    return leads


def _save_lead(lead: dict):
    os.makedirs(os.path.dirname(LEADS_PATH), exist_ok=True)
    if not os.path.exists(LEADS_PATH):
        with open(LEADS_PATH, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"schema": "ravan-leads-v1", "version": 1}) + "\n")
    with open(LEADS_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(lead, ensure_ascii=False) + "\n")


def _update_lead(lead_id: str, updates: dict) -> bool:
    """Rewrite the leads file with one lead updated. Returns True if found."""
    if not os.path.exists(LEADS_PATH):
        return False
    lines = []
    found = False
    with open(LEADS_PATH, encoding="utf-8") as fh:
        for line in fh:
            raw = line.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict) and obj.get("id") == lead_id:
                    obj.update(updates)
                    lines.append(json.dumps(obj, ensure_ascii=False))
                    found = True
                else:
                    lines.append(raw)
            except json.JSONDecodeError:
                lines.append(raw)
    with open(LEADS_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return found


def cmd_add(args) -> int:
    if args.type not in VALID_TYPES:
        print(f"[!] invalid type {args.type!r}. Valid: {sorted(VALID_TYPES)}", file=sys.stderr)
        return 1
    lead = {
        "id": str(uuid.uuid4())[:8],
        "target": args.target or "",
        "type": args.type,
        "value": args.value,
        "source": args.source,
        "why": args.why,
        "status": "open",
        "outcome": None,
        "close_reason": None,
        "discovered_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "closed_at": None,
    }
    _save_lead(lead)
    print(f"[+] Lead {lead['id']} added: {args.type}={args.value} (source: {args.source})")
    return 0


def cmd_list(args) -> int:
    leads = _load_leads(args.target)
    if args.open:
        leads = [l for l in leads if l.get("status") == "open"]
    if not leads:
        print("No leads." if not args.open else f"No open leads. {_OK}")
        return 0
    print(f"{'ID':<10} {'Status':<12} {'Type':<12} {'Value':<40} Why")
    print("-" * 90)
    for l in leads:
        print(f"{l.get('id','?'):<10} {l.get('status','?'):<12} {l.get('type','?'):<12} "
              f"{str(l.get('value',''))[:40]:<40} {l.get('why','')[:50]}")
    return 0


def cmd_explore(args) -> int:
    ok = _update_lead(args.id, {
        "status": "explored",
        "outcome": args.outcome,
        "closed_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    if not ok:
        print(f"[!] Lead {args.id} not found", file=sys.stderr)
        return 1
    print(f"[+] Lead {args.id} marked explored: {args.outcome}")
    return 0


def cmd_close(args) -> int:
    if args.reason not in VALID_REASONS:
        print(f"[!] invalid reason {args.reason!r}. Valid: {sorted(VALID_REASONS)}", file=sys.stderr)
        return 1
    ok = _update_lead(args.id, {
        "status": "closed",
        "close_reason": args.reason,
        "closed_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    if not ok:
        print(f"[!] Lead {args.id} not found", file=sys.stderr)
        return 1
    print(f"[+] Lead {args.id} closed: {args.reason}")
    return 0


def cmd_summary(args) -> int:
    leads = _load_leads(args.target)
    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for l in leads:
        s = l.get("status", "?")
        t = l.get("type", "?")
        by_status[s] = by_status.get(s, 0) + 1
        by_type[t] = by_type.get(t, 0) + 1
    open_count = by_status.get("open", 0)
    print(f"Leads summary{f' for {args.target}' if args.target else ''}:")
    for s, n in sorted(by_status.items()):
        print(f"  {s}: {n}")
    print(f"Types: {dict(sorted(by_type.items()))}")
    if open_count > 0:
        print(f"\n{_WARN}  {open_count} open leads - gate will block until exhausted")
        return 3
    print(f"\n{_OK} No open leads")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Ravan leads ledger — nothing abandoned")
    p.add_argument("--target", help="Filter to this target hostname")
    sub = p.add_subparsers(dest="cmd", required=True)

    add_p = sub.add_parser("add", help="Record a new lead")
    add_p.add_argument("--type", required=True, choices=sorted(VALID_TYPES))
    add_p.add_argument("--value", required=True, help="The discovered value")
    add_p.add_argument("--source", required=True, help="How it was discovered (tool/check name)")
    add_p.add_argument("--why", required=True, help="Why it needs exploration")
    add_p.add_argument("--target", help="Target hostname")

    list_p = sub.add_parser("list", help="List leads")
    list_p.add_argument("--open", action="store_true", help="Only open leads")
    list_p.add_argument("--target")

    exp_p = sub.add_parser("explore", help="Mark a lead as explored with an outcome")
    exp_p.add_argument("id", help="Lead ID")
    exp_p.add_argument("outcome", help='Outcome description e.g. "tested -> clean"')

    cls_p = sub.add_parser("close", help="Close a lead with a reason")
    cls_p.add_argument("id", help="Lead ID")
    cls_p.add_argument("--reason", required=True, choices=sorted(VALID_REASONS))

    sum_p = sub.add_parser("summary", help="Print lead counts")
    sum_p.add_argument("--target")

    args = p.parse_args()
    dispatch = {
        "add": cmd_add, "list": cmd_list, "explore": cmd_explore,
        "close": cmd_close, "summary": cmd_summary,
    }
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
