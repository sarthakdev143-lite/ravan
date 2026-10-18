#!/usr/bin/env python3
"""
calibrate.py — pre-suppress known FPs and adjust check list based on target profile.

    python3 calibrate.py --target https://example.com --profile .opencode/security/profile.md \
        --suppressions .opencode/security/suppressions.md --ledger .opencode/security/findings.jsonl

Outputs a calibration report: which checks to skip, which FPs to pre-suppress,
and severity overrides for this specific target.

Exit codes: 0 = completed, 1 = error
"""

import argparse
import datetime
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

ARCH_SKIP = {
    "static-spa": ["sqli", "rce", "file-upload", "deserialization", "xxe"],
    # Never auto-skip ssrf — even "static" SPAs can have API routes
    "ssr": [],
    "api": ["xss", "clickjacking", "csrf"],
    "cms": [],
    "unknown": [],
}

SEV_BOOST = {
    "static-spa": {"email-auth": 2, "headers": 1},
    "ssr": {"sqli": 1},
    "api": {"bola": 2, "bfla": 1, "mass-assignment": 1},
    "cms": {"plugin-outdated": 2, "admin-exposure": 1},
    "unknown": {},
}

# Patterns that are never pre-suppressed regardless of the suppressions file
_NEVER_SUPPRESS = {"rce", "ssrf", "sql", "injection", "auth", "bypass", "cve"}


def load_profile(path: str) -> dict:
    if not os.path.exists(path):
        return {"architecture": "unknown", "severity_overrides": {}, "skip": []}
    profile: dict = {"architecture": "unknown", "severity_overrides": {}, "skip": []}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("Architecture class:"):
                profile["architecture"] = line.split(":", 1)[1].strip().lower().replace(" ", "-")
            elif line.startswith("Severity overrides:"):
                raw = line.split(":", 1)[1].strip()
                for part in raw.split(","):
                    part = part.strip()
                    if not part:
                        continue
                    if "up-weighted" in part:
                        profile["severity_overrides"][part.split()[0]] = 1
                    elif "down-weighted" in part:
                        profile["severity_overrides"][part.split()[0]] = -1
    return profile


def load_suppressions(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    entries = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("| Pattern"):
                continue
            if line.startswith("|"):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3:
                    pattern = parts[1]
                    reason = parts[2]
                    # Skip empty, wildcard-only, or dangerous class suppression (REV-007)
                    if not pattern or pattern in ("*", ".*", "(example)"):
                        continue
                    pat_lower = pattern.lower()
                    if any(danger in pat_lower for danger in _NEVER_SUPPRESS):
                        continue
                    entries.append({"pattern": pattern, "reason": reason})
    return entries


def calibrate(target: str, profile_path: str, suppressions_path: str, ledger_path: str) -> dict:
    profile = load_profile(profile_path)
    suppressions = load_suppressions(suppressions_path)
    arch = profile.get("architecture", "unknown")

    skip_checks = list(ARCH_SKIP.get(arch, []))
    skip_checks.extend(profile.get("skip", []))
    # Never skip high-impact classes automatically
    for danger in ("rce", "ssrf", "sqli"):
        if danger in skip_checks:
            skip_checks.remove(danger)

    sev_overrides = dict(SEV_BOOST.get(arch, {}))
    sev_overrides.update(profile.get("severity_overrides", {}))

    pre_suppressed = [s["pattern"] for s in suppressions]

    ledger_ids = []
    if os.path.exists(ledger_path):
        with open(ledger_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or '"schema"' in line:
                    continue
                try:
                    entry = json.loads(line)
                    if not isinstance(entry, dict):
                        continue
                    id_ = entry.get("id")
                    if id_:
                        ledger_ids.append(str(id_))
                except json.JSONDecodeError:
                    pass

    return {
        "schema": "ravan-calibration-v1",
        "target": target,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "architecture": arch,
        "skip_checks": sorted(set(skip_checks)),
        "severity_overrides": sev_overrides,
        "pre_suppressed_patterns": pre_suppressed,
        "known_finding_ids": ledger_ids,
        "profile_path": profile_path,
    }


def _safe_out(path: str) -> str:
    """Validate --out path is under reports/ or .opencode/security/. REV-002."""
    if _HAVE_SAFE_WRITE:
        try:
            return _sw.check(path)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            sys.exit(1)
    # Fallback check without engine module
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
    p = argparse.ArgumentParser(description="Calibrate ravan for a specific target")
    p.add_argument("--target", "-t", required=True)
    p.add_argument("--profile", default=".opencode/security/profile.md")
    p.add_argument("--suppressions", default=".opencode/security/suppressions.md")
    p.add_argument("--ledger", default=".opencode/security/findings.jsonl")
    p.add_argument("--out", "-o", help="Write calibration JSON to this path (must be under reports/ or .opencode/security/)")
    args = p.parse_args()

    result = calibrate(args.target, args.profile, args.suppressions, args.ledger)
    out = json.dumps(result, indent=2)
    if args.out:
        safe_path = _safe_out(args.out)
        os.makedirs(os.path.dirname(safe_path) or ".", exist_ok=True)
        with open(safe_path, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"[+] calibration -> {safe_path}")
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
