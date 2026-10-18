#!/usr/bin/env python3
"""
doctor.py — Ravan tool audit + preflight. Merged from opencode-pentester.

Checks all security tools, grouped by domain. For no-escape mode: lists
missing tools and asks the user once if they want to install.

Usage:
    python3 engine/doctor.py                          # full audit (text)
    python3 engine/doctor.py --json                   # JSON output
    python3 engine/doctor.py --domain Recon           # one domain
    python3 engine/doctor.py --required-only          # only missing required
    python3 engine/doctor.py --install-command <tool> # print install command for tool

Exit codes: 0 = all required tools present, 1 = missing required tools
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from typing import Any

# Windows cmd/PowerShell may not support Unicode — use ASCII fallbacks
_OK   = "[+]" if os.name == "nt" else "✔"
_MISS = "[!]" if os.name == "nt" else "✘"
_OPT  = "[-]" if os.name == "nt" else "○"

# Tool registry: name → (domain, category, install_command, fallback_description)
# category: "required" | "recommended" | "optional"
TOOLS: list[tuple[str, str, str, str, str]] = [
    # ── Core ────────────────────────────────────────────────────────
    ("python3",       "Core",     "required",    "built-in (Windows: use 'python' alias)",            "required runtime"),
    ("git",           "Core",     "required",    "https://git-scm.com/downloads",                    "version control"),
    ("curl",          "Core",     "required",    "built-in on most systems",                          "HTTP requests"),
    ("openssl",       "Core",     "required",    "built-in on most systems",                          "TLS inspection"),
    ("nslookup",      "Core",     "required",    "built-in on most systems",                          "DNS queries"),
    ("dig",           "Core",     "recommended", "apt install dnsutils / brew install bind",          "DNS queries (richer than nslookup)"),
    # ── Recon ───────────────────────────────────────────────────────
    ("subfinder",     "Recon",    "recommended", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "subdomain enumeration"),
    ("amass",         "Recon",    "optional",    "go install -v github.com/owasp-amass/amass/v4/...@master",                   "deep subdomain enumeration"),
    ("dnsx",          "Recon",    "recommended", "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",             "DNS resolution at scale"),
    ("httpx",         "Recon",    "recommended", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",           "HTTP probing + tech fingerprinting"),
    ("katana",        "Recon",    "recommended", "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",         "web crawling"),
    ("gau",           "Recon",    "optional",    "go install -v github.com/lc/gau/v2/cmd/gau@latest",                         "fetching known URLs (Wayback/Common Crawl)"),
    ("whatweb",       "Recon",    "optional",    "apt install whatweb / gem install whatweb",                                  "web tech fingerprinting"),
    ("whois",         "Recon",    "recommended", "apt install whois / built-in on most systems",                               "domain registration info"),
    # ── Discovery ───────────────────────────────────────────────────
    ("ffuf",          "Discovery","recommended", "go install github.com/ffuf/ffuf/v2@latest",                                  "directory + parameter fuzzing"),
    ("gobuster",      "Discovery","optional",    "apt install gobuster / go install github.com/OJ/gobuster/v3@latest",         "directory brute-forcing"),
    ("arjun",         "Discovery","recommended", "pip install arjun",                                                          "HTTP parameter discovery"),
    ("wfuzz",         "Discovery","optional",    "pip install wfuzz",                                                          "web fuzzer"),
    # ── Scanning ────────────────────────────────────────────────────
    ("nuclei",        "Scanning", "recommended", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",      "template-based scanner"),
    ("nikto",         "Scanning", "optional",    "apt install nikto",                                                          "web server scanner"),
    ("nmap",          "Scanning", "optional",    "https://nmap.org/download / apt install nmap",                               "port + service scanner (operator-run only)"),
    ("dalfox",        "Scanning", "optional",    "go install github.com/hahwul/dalfox/v2@latest",                              "XSS scanner"),
    # ── Injection ───────────────────────────────────────────────────
    ("sqlmap",        "Injection","optional",    "apt install sqlmap / pip install sqlmap",                                    "SQL injection (operator-run only)"),
    # ── SAST / Secrets ──────────────────────────────────────────────
    ("semgrep",       "SAST",     "recommended", "pip install semgrep",                                                        "static analysis"),
    ("bandit",        "SAST",     "optional",    "pip install bandit",                                                         "Python SAST"),
    ("gitleaks",      "SAST",     "recommended", "go install github.com/gitleaks/gitleaks/v8@latest",                          "secret scanning"),
    ("trufflehog",    "SAST",     "optional",    "pip install trufflehog",                                                     "deep secret scanning (git history)"),
    # ── Auth / JWT ──────────────────────────────────────────────────
    ("jwt_tool",      "Auth",     "optional",    "pip install jwt_tool",                                                       "JWT testing"),
    # ── Cloud ───────────────────────────────────────────────────────
    ("trivy",         "Cloud",    "optional",    "https://aquasecurity.github.io/trivy/",                                      "container + IaC scanning"),
    ("prowler",       "Cloud",    "optional",    "pip install prowler",                                                        "AWS/Azure/GCP security audit"),
]

FALLBACKS: dict[str, str] = {
    "gitleaks":   "grep -rInE '(api[_-]?key|secret|passwd|token|AKIA)[\"\\']?\\s*[:=]\\s*[\"\\'][A-Za-z0-9+/_-]{16,}' .",
    "trufflehog": "git log -p | grep -iE '(password|secret|token|key)\\s*=\\s*[A-Za-z0-9+/_-]{16,}'",
    "semgrep":    "grep -rn 'eval\\|exec\\|subprocess\\|os.system\\|innerHTML\\|dangerouslySetInnerHTML\\|pickle.loads' .",
    "bandit":     "grep -rn 'assert\\|exec(\\|eval(\\|pickle\\|yaml.load(' .",
    "nuclei":     "curl -sSI <target> (manual header/method checks per CVE path)",
    "sqlmap":     "manual: boolean/error/time-based payloads per parameter",
    "ffuf":       "curl -s https://<target>/<word> (wordlist loop via bash/python)",
    "gobuster":   "same as ffuf fallback",
    "nikto":      "curl -sSI --max-time 10 <target> (check headers + HTTP methods manually)",
    "jwt_tool":   "base64 decode header/payload, craft alg=none or weak-secret payload manually",
    "dalfox":     "curl with encoded XSS payloads per parameter (reflected input check)",
    "subfinder":  "crt.sh + dnsx: python3 .opencode/skills/web-recon-passive/scripts/recon.py (CT log check)",
    "amass":      "subfinder fallback + crt.sh query",
    "dnsx":       "nslookup / dig in a loop",
    "httpx":      "curl -sSI batch loop",
    "katana":     "wget --spider or curl + HTML link extraction",
    "whatweb":    "read Server/X-Powered-By response headers",
    "whois":      "RDAP: https://rdap.org/domain/<domain>",
    "arjun":      "manual: try common parameter names (id, user, page, q, search, token)",
    "nmap":       "ping + curl + openssl (passive only - nmap is operator-run)",
    "prowler":    "manual AWS console + AWS CLI checks",
    "trivy":      "pip-audit / npm audit / cargo audit per ecosystem",
}


def _check_tool(binary: str) -> bool:
    """Check if a binary exists in PATH. Handles Windows Python aliases."""
    if shutil.which(binary) is not None:
        return True
    # Windows: python3 → python (if it's Python 3)
    if binary == "python3" and os.name == "nt":
        python = shutil.which("python")
        if python:
            try:
                r = subprocess.run([python, "--version"], capture_output=True, text=True, timeout=5)
                return r.returncode == 0 and "Python 3" in r.stdout + r.stderr
            except Exception:
                pass
    # Windows: openssl may be bundled with git
    if binary == "openssl" and os.name == "nt":
        for candidate in [
            r"C:\Program Files\Git\usr\bin\openssl.exe",
            r"C:\Program Files (x86)\Git\usr\bin\openssl.exe",
        ]:
            if os.path.isfile(candidate):
                return True
    return False


def audit(domain_filter: str | None = None) -> dict[str, Any]:
    """
    Run a full tool audit. Returns a dict keyed by tool name.
    """
    results: dict[str, Any] = {}
    for name, domain, category, install, desc in TOOLS:
        if domain_filter and domain.lower() != domain_filter.lower():
            continue
        present = _check_tool(name)
        results[name] = {
            "domain": domain,
            "category": category,
            "present": present,
            "install": install,
            "description": desc,
            "fallback": FALLBACKS.get(name),
        }
    return results


def summary(results: dict[str, Any]) -> dict[str, Any]:
    total = len(results)
    present = sum(1 for v in results.values() if v["present"])
    missing_required = [k for k, v in results.items() if not v["present"] and v["category"] == "required"]
    missing_recommended = [k for k, v in results.items() if not v["present"] and v["category"] == "recommended"]
    return {
        "total": total,
        "present": present,
        "missing_required": missing_required,
        "missing_recommended": missing_recommended,
        "all_required_present": len(missing_required) == 0,
    }


def format_text(results: dict[str, Any], required_only: bool = False) -> str:
    lines = ["Ravan tool audit", "=" * 40]
    current_domain = None
    for name, info in sorted(results.items(), key=lambda x: (x[1]["domain"], x[0])):
        if required_only and info["present"]:
            continue
        if info["domain"] != current_domain:
            current_domain = info["domain"]
            lines.append(f"\n-- {current_domain} --")
        icon = _OK if info["present"] else (_MISS if info["category"] == "required" else _OPT)
        status = "INSTALLED" if info["present"] else f"MISSING ({info['category']})"
        lines.append(f"  {icon} {name:<20} {status}")
        if not info["present"]:
            lines.append(f"    install: {info['install']}")
            if info.get("fallback"):
                lines.append(f"    fallback: {info['fallback']}")
    s = summary(results)
    lines.append(f"\n{s['present']}/{s['total']} tools available")
    if s["missing_required"]:
        lines.append(f"MISSING REQUIRED: {', '.join(s['missing_required'])}")
    if s["missing_recommended"]:
        lines.append(f"missing recommended: {', '.join(s['missing_recommended'])}")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description="Ravan tool audit + preflight")
    p.add_argument("--json", action="store_true", dest="as_json")
    p.add_argument("--domain", help="Filter to one domain (Recon, Scanning, SAST, ...)")
    p.add_argument("--required-only", action="store_true", help="Show only missing required tools")
    p.add_argument("--install-command", metavar="TOOL",
                   help="Print the install command for a specific tool and exit")
    args = p.parse_args()

    if args.install_command:
        tool_name = args.install_command.lower()
        for name, domain, category, install, desc in TOOLS:
            if name.lower() == tool_name:
                print(f"{name}: {install}")
                if FALLBACKS.get(name):
                    print(f"fallback: {FALLBACKS[name]}")
                return 0
        print(f"[!] Unknown tool: {args.install_command}", file=sys.stderr)
        return 1

    results = audit(args.domain)
    s = summary(results)

    if args.as_json:
        print(json.dumps({"tools": results, "summary": s}, indent=2))
    else:
        print(format_text(results, args.required_only))

    return 0 if s["all_required_present"] else 1


if __name__ == "__main__":
    sys.exit(main())
