#!/usr/bin/env python3
"""
ledger_append.py — atomic, validated ledger writer. Fixes REV-005.

The verifier and other agents must use this script — not open() directly —
to append to the findings ledger. It enforces schema, prevents duplicate IDs
for base findings, and hard-codes the ledger path so no agent can redirect
writes elsewhere.

Usage:
    python3 engine/ledger_append.py --json '{"id":"RVN-001",...}'
    python3 engine/ledger_append.py --file /path/to/finding.json
    python3 engine/ledger_append.py --verification RVN-001 --verdict fixed --evidence-ref path/to/new.json

Exit codes: 0 = written, 1 = validation error, 2 = duplicate ID
"""

import argparse
import datetime
import json
import os
import sys

LEDGER_PATH = os.path.join(".opencode", "security", "findings.jsonl")

REQUIRED_FINDING_FIELDS = {"id", "target", "check", "title", "severity", "status"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_STATUSES = {"open", "verified-fixed", "verified-present", "indeterminate", "suppressed"}
VALID_VERDICTS = {"exploitable", "gated", None}
VALID_CONFIDENCES = {"high", "medium", "low"}


def _read_existing_ids() -> set[str]:
    if not os.path.exists(LEDGER_PATH):
        return set()
    ids = set()
    with open(LEDGER_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    continue
                # Schema header and verification records don't count as base finding IDs
                schema = obj.get("schema", "")
                if schema in ("ravan-findings-v1", "ravan-verification-v1", "ravan-scout-v1"):
                    continue
                id_ = obj.get("id")
                if id_:
                    ids.add(str(id_))
            except json.JSONDecodeError:
                pass
    return ids


def _validate_finding(record: dict) -> tuple[bool, str]:
    """Validate a base finding record."""
    missing = REQUIRED_FINDING_FIELDS - set(record.keys())
    if missing:
        return False, f"missing required fields: {sorted(missing)}"

    if record["severity"] not in VALID_SEVERITIES:
        return False, f"invalid severity {record['severity']!r} (valid: {sorted(VALID_SEVERITIES)})"

    if record["status"] not in VALID_STATUSES:
        return False, f"invalid status {record['status']!r} (valid: {sorted(VALID_STATUSES)})"

    verdict = record.get("verdict")
    if verdict is not None and verdict not in VALID_VERDICTS:
        return False, f"invalid verdict {verdict!r} (valid: exploitable, gated, or omit)"

    confidence = record.get("confidence")
    if confidence is not None and confidence not in VALID_CONFIDENCES:
        return False, f"invalid confidence {confidence!r} (valid: {sorted(VALID_CONFIDENCES)})"

    return True, ""


def _validate_verification(record: dict) -> tuple[bool, str]:
    """Validate a verification record."""
    required = {"finding_id", "verdict", "verified_at"}
    missing = required - set(record.keys())
    if missing:
        return False, f"missing required fields: {sorted(missing)}"
    valid_v = {"fixed", "still-present", "changed", "indeterminate"}
    if record["verdict"] not in valid_v:
        return False, f"invalid verdict {record['verdict']!r} (valid: {sorted(valid_v)})"
    return True, ""


def _ensure_ledger_dir():
    os.makedirs(os.path.dirname(LEDGER_PATH), exist_ok=True)


def append_finding(record: dict) -> tuple[bool, str]:
    """Validate and append a base finding. Returns (ok, error_message)."""
    ok, reason = _validate_finding(record)
    if not ok:
        return False, reason

    existing_ids = _read_existing_ids()
    if str(record["id"]) in existing_ids:
        return False, f"duplicate ID {record['id']!r} already in ledger (use --verification to update)"

    record.setdefault("first_seen", datetime.date.today().isoformat())
    record.setdefault("last_seen", datetime.date.today().isoformat())

    _ensure_ledger_dir()
    with open(LEDGER_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return True, ""


def append_verification(finding_id: str, verdict: str,
                        evidence_ref: str, requests_used: int = 0) -> tuple[bool, str]:
    """Append a verification record for a finding. Does NOT edit the original finding."""
    existing_ids = _read_existing_ids()
    # For verification, the finding_id must exist (we check base IDs as approximate proxy)
    # We allow it even if not found because the ledger may have been rotated.
    record = {
        "schema": "ravan-verification-v1",
        "finding_id": finding_id,
        "verdict": verdict,
        "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "evidence_ref": evidence_ref,
        "requests_used": requests_used,
    }
    ok, reason = _validate_verification(record)
    if not ok:
        return False, reason

    _ensure_ledger_dir()
    with open(LEDGER_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return True, ""


def main() -> int:
    p = argparse.ArgumentParser(
        description="Append a validated finding or verification record to the ravan ledger."
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--json", "-j", dest="json_str",
                       help="Finding JSON string (single line)")
    group.add_argument("--file", "-f",
                       help="Path to a JSON file containing the finding")
    group.add_argument("--verification", dest="finding_id",
                       help="Append a verification record for this finding ID")

    p.add_argument("--verdict", choices=["fixed", "still-present", "changed", "indeterminate"],
                   help="Verdict for --verification")
    p.add_argument("--evidence-ref", default="",
                   help="Path/ref to the new evidence file for --verification")
    p.add_argument("--requests-used", type=int, default=0,
                   help="Number of requests used in re-test")
    args = p.parse_args()

    if args.finding_id:
        if not args.verdict:
            print("[!] --verdict is required with --verification", file=sys.stderr)
            return 1
        ok, reason = append_verification(
            args.finding_id, args.verdict, args.evidence_ref, args.requests_used
        )
        if not ok:
            print(f"[!] {reason}", file=sys.stderr)
            return 1
        print(f"[+] Verification record appended: {args.finding_id} -> {args.verdict}")
        return 0

    # Load finding JSON
    if args.json_str:
        raw = args.json_str
    else:
        try:
            with open(args.file, encoding="utf-8") as fh:
                raw = fh.read()
        except (OSError, IOError) as exc:
            print(f"[!] Cannot read {args.file}: {exc}", file=sys.stderr)
            return 1

    try:
        record = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"[!] Invalid JSON: {exc}", file=sys.stderr)
        return 1

    if not isinstance(record, dict):
        print("[!] Finding must be a JSON object, not a list or scalar", file=sys.stderr)
        return 1

    ok, reason = append_finding(record)
    if not ok:
        code = 2 if "duplicate" in reason else 1
        print(f"[!] {reason}", file=sys.stderr)
        return code

    print(f"[+] Finding {record['id']} ({record['severity']}) appended to {LEDGER_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
