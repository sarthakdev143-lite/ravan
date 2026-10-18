#!/usr/bin/env python3
"""
trend.py — posture trend analysis across consecutive assessment reports.

    python3 trend.py --reports reports/example.com/ --out reports/example.com/trend.json

Reads all <host>-*.json report files, computes posture score over time,
identifies new vs. resolved findings, and produces a posture timeline.

Exit codes: 0 = completed, 1 = error, 2 = insufficient data (needs 2+ reports)
"""

import argparse
import datetime
import glob
import json
import os
import sys

# Bootstrap engine path for safe_write
_ENGINE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))), "engine")
if os.path.isdir(_ENGINE):
    sys.path.insert(0, _ENGINE)
    try:
        import safe_write as _sw
        _HAVE_SAFE_WRITE = True
    except ImportError:
        _HAVE_SAFE_WRITE = False
else:
    _HAVE_SAFE_WRITE = False

REPORT_SCHEMA = "ravan-findings-v1"  # schema field NOT present means it's a report


def load_reports(reports_dir: str) -> list[dict]:
    """Load all assessment report JSON files from reports_dir. REV-007 fixes applied."""
    # Escape the directory path before globbing (REV-007)
    safe_dir = glob.escape(os.path.realpath(reports_dir))
    pattern = os.path.join(safe_dir, "*-*.json")
    files = sorted(glob.glob(pattern))
    reports = []
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            # REV-007: per-file error, not abort
            print(f"[!] Skipping {f}: cannot parse", file=sys.stderr)
            continue

        if not isinstance(data, dict):
            continue  # REV-007: skip non-dict JSON

        # Skip calibration files and other non-report JSON (REV-007)
        if data.get("schema") in (
            "ravan-calibration-v1", "ravan-scout-v1",
            "ravan-active-policy-v1", "ravan-active-policy-v2",
            "ravan-leads-v1", "ravan-findings-v1",
        ):
            continue

        facts = data.get("facts")
        if not isinstance(facts, dict):
            continue

        meta = facts.get("meta") or {}
        posture = facts.get("posture") or {}
        raw_findings = data.get("findings") or []
        if not isinstance(raw_findings, list):
            raw_findings = []

        finding_ids = []
        for f_ in raw_findings:
            if not isinstance(f_, dict):
                continue
            id_ = f_.get("id")
            if id_ is not None:
                finding_ids.append(str(id_))

        # Sort by assessed_at, not filename (REV-007)
        assessed_at = str(meta.get("assessed_at") or "")

        reports.append({
            "file": f,
            "date": assessed_at,
            "score": posture.get("score"),
            "grade": posture.get("grade"),
            "finding_ids": finding_ids,
            "severity_counts": _count_by_severity(raw_findings),
            "total_findings": len(raw_findings),
        })

    # Sort by date field, fall back to filename (REV-007)
    reports.sort(key=lambda r: (r["date"] or "", r["file"]))
    return reports


def _count_by_severity(findings: list) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def compute_trend(reports: list[dict]) -> dict:
    if len(reports) < 2:
        return {}

    first, last = reports[0], reports[-1]
    score_first = first.get("score") or 0
    score_last = last.get("score") or 0
    score_delta = score_last - score_first

    first_ids = set(first["finding_ids"])
    last_ids = set(last["finding_ids"])
    new_ids = sorted(str(x) for x in last_ids - first_ids)
    resolved_ids = sorted(str(x) for x in first_ids - last_ids)

    if score_delta > 5:
        direction = "improving"
    elif score_delta < -5:
        direction = "degrading"
    else:
        direction = "stable"

    return {
        "schema": "ravan-trend-v1",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "report_count": len(reports),
        "first_assessment": first["date"],
        "last_assessment": last["date"],
        "score_first": score_first,
        "score_last": score_last,
        "score_delta": score_delta,
        "direction": direction,
        "finding_count_first": first["total_findings"],
        "finding_count_last": last["total_findings"],
        "finding_count_delta": last["total_findings"] - first["total_findings"],
        "new_finding_ids": new_ids,
        "resolved_finding_ids": resolved_ids,
        "timeline": [
            {
                "date": r["date"],
                "score": r["score"],
                "grade": r["grade"],
                "total_findings": r["total_findings"],
                "severity": r["severity_counts"],
            }
            for r in reports
        ],
    }


def _safe_out(path: str) -> str:
    """Validate --out path is under reports/. REV-002."""
    if _HAVE_SAFE_WRITE:
        try:
            return _sw.check(path)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            sys.exit(1)
    real = os.path.realpath(path)
    allowed = [
        os.path.realpath("reports"),
        os.path.realpath(os.path.join(".opencode", "security")),
    ]
    for root in allowed:
        try:
            if os.path.commonpath([real, root]) == root:
                return real
        except ValueError:
            pass
    print(f"[!] --out path {path!r} must be under reports/ or .opencode/security/", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    p = argparse.ArgumentParser(description="Compute posture trend across reports")
    p.add_argument("--reports", "-r", required=True,
                   help="Directory containing report JSON files")
    p.add_argument("--out", "-o",
                   help="Write trend JSON here (must be under reports/ or .opencode/security/)")
    args = p.parse_args()

    if not os.path.isdir(args.reports):
        print(f"[!] Not a directory: {args.reports}", file=sys.stderr)
        return 1

    reports = load_reports(args.reports)
    if len(reports) < 2:
        print("[!] Need at least 2 valid assessment reports for trend analysis", file=sys.stderr)
        print(f"    Found {len(reports)} valid report(s) in {args.reports}", file=sys.stderr)
        return 2

    trend = compute_trend(reports)
    out = json.dumps(trend, indent=2)

    if args.out:
        safe_path = _safe_out(args.out)
        os.makedirs(os.path.dirname(safe_path) or ".", exist_ok=True)
        with open(safe_path, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"[+] trend -> {safe_path}")

    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
