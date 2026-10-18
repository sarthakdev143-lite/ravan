#!/usr/bin/env python3
"""
scout_run.py — authorized scanner wrapper. Fixes REV-003.

Wraps Nuclei and Semgrep with:
  - Hard policy_check.py gate before ANY scan
  - Fixed Tier 1 tags (no intrusive/fuzzing without Tier 2 + explicit flag)
  - Fixed output directory under .opencode/security/scan-results/
  - Scope enforcement (target in scope.included, not in excluded)
  - Missing-tool detection and ask-once workflow

Usage:
    python3 engine/scout_run.py --target https://example.com [--scanner nuclei|semgrep|both]
    python3 engine/scout_run.py --target https://example.com --tier 2 --confirm-tier2
    python3 engine/scout_run.py --source-path ./src --scanner semgrep  # Mode 2 code audit

Exit codes:
    0 = success
    1 = scan error
    2 = authorization blocked
    127 = required tool not installed
"""

import argparse
import datetime
import json
import os
import subprocess
import sys

# Bootstrap engine module path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import policy_check
import safe_write

SCAN_RESULTS_DIR = os.path.join(".opencode", "security", "scan-results")

# Fixed Tier 1 tags — never include intrusive/fuzzing/dos/rce without Tier 2
TIER1_TAGS = "cves,vulnerabilities,exposure,misconfig,tech"
TIER2_TAGS = "cves,vulnerabilities,exposure,misconfig,tech,intrusive"


def _tool_available(binary: str) -> bool:
    try:
        result = subprocess.run(
            [binary, "--version"], capture_output=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _run_nuclei(target: str, tags: str, output_path: str, rate_limit: int = 100) -> tuple[int, str]:
    cmd = [
        "nuclei",
        "-u", target,
        "-tags", tags,
        "-jsonl",
        "-o", output_path,
        "-rate-limit", str(rate_limit),
        "-silent",
        "-no-color",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        return result.returncode, result.stderr[:2000]
    except FileNotFoundError:
        return 127, "nuclei not found"
    except subprocess.TimeoutExpired:
        return 1, "nuclei timed out (30m)"


def _run_semgrep(source_path: str, output_path: str) -> tuple[int, str]:
    cmd = [
        "semgrep",
        "--config", "auto",
        "--json",
        "--output", output_path,
        "--no-rewrite-rule-ids",
        source_path,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return result.returncode, result.stderr[:2000]
    except FileNotFoundError:
        return 127, "semgrep not found"
    except subprocess.TimeoutExpired:
        return 1, "semgrep timed out (10m)"


def _normalize_nuclei(raw_path: str, target: str) -> list[dict]:
    findings = []
    if not os.path.exists(raw_path):
        return findings
    with open(raw_path, encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info") or {}
            sev = str(info.get("severity") or "info").lower()
            if sev not in ("critical", "high", "medium", "low", "info"):
                sev = "info"
            findings.append({
                "id": f"SCOUT-NUCLEI-{i+1:04d}",
                "title": info.get("name") or item.get("template-id") or "Unknown",
                "severity": sev,
                "category": item.get("type") or "nuclei",
                "evidence": [
                    item.get("matched-at") or target,
                    *([str(item["extracted-results"])] if item.get("extracted-results") else []),
                ],
                "cvss": str(info.get("cvss-score") or ""),
                "confidence": "high" if sev in ("critical", "high") else "medium",
                "verdict": "exploitable" if sev in ("critical", "high") else "gated",
                "raw_tool": "nuclei",
                "raw_id": item.get("template-id") or "",
                "tags": info.get("tags") or [],
            })
    return findings


def _normalize_semgrep(raw_path: str) -> list[dict]:
    findings = []
    if not os.path.exists(raw_path):
        return findings
    try:
        with open(raw_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return findings
    if not isinstance(data, dict):
        return findings
    for i, result in enumerate(data.get("results") or []):
        sev = str(result.get("extra", {}).get("severity") or "WARNING").upper()
        sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}
        severity = sev_map.get(sev, "info")
        findings.append({
            "id": f"SCOUT-SEMGREP-{i+1:04d}",
            "title": result.get("check_id") or "semgrep-finding",
            "severity": severity,
            "category": "sast",
            "evidence": [
                f"{result.get('path','')}:{result.get('start',{}).get('line','')}",
                result.get("extra", {}).get("message") or "",
            ],
            "cvss": "",
            "confidence": "high" if severity in ("critical", "high") else "medium",
            "verdict": "exploitable" if severity in ("critical", "high") else "gated",
            "raw_tool": "semgrep",
            "raw_id": result.get("check_id") or "",
        })
    return findings


def main() -> int:
    p = argparse.ArgumentParser(description="Authorized scanner wrapper with scope enforcement.")
    p.add_argument("--target", "-t", help="Target URL (required for Nuclei)")
    p.add_argument("--source-path", "-s",
                   help="Local source directory for Semgrep (Mode 2 code audit)")
    p.add_argument("--scanner", choices=["nuclei", "semgrep", "both"], default="nuclei")
    p.add_argument("--tier", type=int, choices=[1, 2], default=1,
                   help="Authorization tier (1=safe active, 2=intrusive)")
    p.add_argument("--confirm-tier2", action="store_true",
                   help="Required explicit flag to run Tier 2 (intrusive) scans")
    p.add_argument("--rate-limit", type=int, default=100,
                   help="Nuclei requests/sec (default 100)")
    args = p.parse_args()

    if args.scanner in ("nuclei", "both") and not args.target:
        print("[!] --target is required for nuclei scans", file=sys.stderr)
        return 1

    if args.tier == 2 and not args.confirm_tier2:
        print("[!] Tier 2 (intrusive) requires --confirm-tier2 flag", file=sys.stderr)
        print("    This flag must be set by the orchestrator after per-run user confirmation.")
        return 1

    # Authorization gate
    if args.target:
        host = args.target
        for prefix in ("https://", "http://"):
            if host.startswith(prefix):
                host = host[len(prefix):]
        host = host.split("/")[0].split(":")[0]
        code, reason, message = policy_check.check(host, args.tier)
        if code != 0:
            print(json.dumps({"status": "blocked", "reason": reason, "message": message}))
            print(f"[!] BLOCKED: {message}", file=sys.stderr)
            return 2

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    host_slug = (host if args.target else "local").replace(".", "_")
    os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)

    findings: list[dict] = []
    stats: dict = {}

    if args.scanner in ("nuclei", "both") and args.target:
        if not _tool_available("nuclei"):
            print(json.dumps({
                "status": "missing-tool",
                "tool": "nuclei",
                "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "message": "nuclei not installed. Ask user: 'May I install nuclei? (go install ...)'"
            }))
            return 127

        tags = TIER2_TAGS if args.tier == 2 else TIER1_TAGS
        raw_file = f"{host_slug}-nuclei-{stamp}.jsonl"
        raw_path = safe_write.check(os.path.join(SCAN_RESULTS_DIR, raw_file))
        rc, stderr = _run_nuclei(args.target, tags, raw_path, args.rate_limit)
        nuclei_findings = _normalize_nuclei(raw_path, args.target)
        findings.extend(nuclei_findings)
        stats["nuclei"] = {"exit": rc, "findings": len(nuclei_findings), "raw": raw_path}
        if rc not in (0, 1):  # nuclei exits 1 when it finds vulns
            print(f"[!] nuclei exit {rc}: {stderr}", file=sys.stderr)

    if args.scanner in ("semgrep", "both"):
        source = args.source_path or "."
        if not _tool_available("semgrep"):
            print(json.dumps({
                "status": "missing-tool",
                "tool": "semgrep",
                "install": "pip install semgrep",
                "message": "semgrep not installed. Ask user: 'May I install semgrep? (pip install semgrep)'"
            }))
            return 127
        raw_file = f"{host_slug}-semgrep-{stamp}.json"
        raw_path = safe_write.check(os.path.join(SCAN_RESULTS_DIR, raw_file))
        rc, stderr = _run_semgrep(source, raw_path)
        sg_findings = _normalize_semgrep(raw_path)
        findings.extend(sg_findings)
        stats["semgrep"] = {"exit": rc, "findings": len(sg_findings), "raw": raw_path}

    result = {
        "schema": "ravan-scout-v1",
        "target": args.target or args.source_path or ".",
        "scanner": args.scanner,
        "tier": args.tier,
        "findings": findings,
        "scan_stats": stats,
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    out_file = f"{host_slug}-scout-{stamp}.json"
    out_path = safe_write.check(os.path.join(SCAN_RESULTS_DIR, out_file))
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(f"[+] {len(findings)} findings -> {out_path}", file=sys.stderr)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
