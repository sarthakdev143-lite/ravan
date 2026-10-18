#!/usr/bin/env python3
"""
policy_check.py — active-policy.json enforcement. Fixes REV-004.

Every check that was previously "read the JSON and decide in prose"
is now enforced in code. Exits non-zero if authorization is missing,
expired, out-of-scope, or the requested tier is not enabled.

Usage:
    python3 engine/policy_check.py <target> <tier>      # check only
    python3 engine/policy_check.py <target> <tier> --create-default  # write template policy

Exit codes: 0 = authorized, 1 = blocked, 2 = error
"""

import argparse
import datetime
import fnmatch
import json
import os
import sys

POLICY_DIR = os.path.join(".opencode", "security", "policies")
LEGACY_POLICY = os.path.join(".opencode", "security", "active-policy.json")

POLICY_TEMPLATE = {
    "schema": "ravan-active-policy-v2",
    "target": "REPLACE_ME",
    "authorized": False,
    "owner_asserted": False,
    "expires": None,
    "tiers": {
        "tier0_passive": {
            "enabled": True,
            "description": "Passive recon — DNS, TLS, headers, public JS analysis."
        },
        "tier1_safe_active": {
            "enabled": False,
            "description": "Safe active — Nuclei cves/exposure/misconfig/tech, Semgrep SAST, CORS/JWT probe."
        },
        "tier2_intrusive": {
            "enabled": False,
            "description": "Intrusive — Nuclei intrusive/fuzzing tags, injection probing. Per-run confirmation required."
        },
        "tier3_destructive": {
            "enabled": False,
            "description": "Destructive — never auto-authorized."
        }
    },
    "scope": {
        "included": ["REPLACE_ME"],
        "excluded": []
    },
    "max_requests": 1000,
    "emergency_contact": "",
    "stop_conditions": [
        "target returns 5xx errors",
        "WAF/rate-limiting blocks",
        "owner requests stop"
    ]
}


def _host_from_target(target: str) -> str:
    """Extract hostname from a URL or bare host."""
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split("/")[0].split(":")[0].lower()


def _load_policy(host: str) -> tuple[dict | None, str | None]:
    """Load per-host policy or fall back to legacy file."""
    per_host = os.path.join(POLICY_DIR, f"{host}.json")
    if os.path.exists(per_host):
        with open(per_host, encoding="utf-8") as fh:
            return json.load(fh), per_host
    if os.path.exists(LEGACY_POLICY):
        with open(LEGACY_POLICY, encoding="utf-8") as fh:
            return json.load(fh), LEGACY_POLICY
    return None, None


def _host_in_scope(host: str, scope: dict) -> tuple[bool, str]:
    """Check host against scope.included / scope.excluded patterns."""
    excluded = scope.get("excluded") or []
    included = scope.get("included") or []

    for pattern in excluded:
        if fnmatch.fnmatch(host, pattern) or host == pattern:
            return False, f"host {host!r} matches exclusion {pattern!r}"

    if not included:
        return True, "no include list — host in scope"

    for pattern in included:
        if fnmatch.fnmatch(host, pattern) or host == pattern:
            return True, f"host {host!r} matches {pattern!r}"

    return False, f"host {host!r} not in scope (included: {included})"


def check(host: str, tier: int) -> tuple[int, str, str]:
    """
    Validate authorization for host + tier.

    Returns (exit_code, reason_slug, human_message).
    exit_code 0 = authorized, 1 = blocked.
    """
    policy, policy_file = _load_policy(host)

    if policy is None:
        return 1, "no-policy", (
            f"No policy found for {host!r}. "
            f"Create {POLICY_DIR}/{host}.json or run with --create-default."
        )

    if not policy.get("authorized"):
        return 1, "not-authorized", f"Policy {policy_file}: authorized=false"

    if not policy.get("owner_asserted"):
        return 1, "owner-not-asserted", f"Policy {policy_file}: owner_asserted=false"

    # Expiry check — null expiry is invalid for Tier 1+
    expires = policy.get("expires")
    if tier >= 1:
        if expires is None:
            return 1, "no-expiry", (
                "Tier 1+ requires a non-null expires field in the policy. "
                "Set an ISO-8601 datetime, e.g. '2026-10-19T00:00:00Z'."
            )
        try:
            exp_dt = datetime.datetime.fromisoformat(
                expires.replace("Z", "+00:00") if expires.endswith("Z") else expires
            )
            now = datetime.datetime.now(datetime.timezone.utc)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=datetime.timezone.utc)
            if exp_dt <= now:
                return 1, "expired", f"Policy expired at {expires} (now {now.isoformat()})"
        except (ValueError, AttributeError) as exc:
            return 1, "invalid-expiry", f"Cannot parse expires {expires!r}: {exc}"

    # Scope check
    scope = policy.get("scope") or {}
    ok, reason = _host_in_scope(host, scope)
    if not ok:
        return 1, "out-of-scope", reason

    # Tier check
    tier_key_map = {
        0: "tier0_passive",
        1: "tier1_safe_active",
        2: "tier2_intrusive",
        3: "tier3_destructive",
    }
    tier_key = tier_key_map.get(tier, f"tier{tier}")
    tiers = policy.get("tiers") or {}
    tier_cfg = tiers.get(tier_key) or {}
    if not tier_cfg.get("enabled"):
        return 1, "tier-not-enabled", (
            f"Tier {tier} ({tier_key}) is not enabled in {policy_file}. "
            f"Set tiers.{tier_key}.enabled=true to authorize."
        )

    expires_str = expires or "no expiry (Tier 0)"
    return 0, "authorized", (
        f"Authorization confirmed: {host} @ Tier {tier} "
        f"(policy: {policy_file}, expires: {expires_str})"
    )


def create_policy(host: str, tier: int = 0) -> str:
    """Write a template policy for host. Returns the path written."""
    os.makedirs(POLICY_DIR, exist_ok=True)
    policy = dict(POLICY_TEMPLATE)
    policy["target"] = host
    policy["scope"] = {"included": [host, f"*.{host}"], "excluded": []}
    policy["tiers"]["tier0_passive"]["enabled"] = True
    if tier >= 1:
        policy["tiers"]["tier1_safe_active"]["enabled"] = False  # still needs manual enable
    path = os.path.join(POLICY_DIR, f"{host}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(policy, fh, indent=2)
    return path


def main() -> int:
    p = argparse.ArgumentParser(
        description="Validate active-policy.json authorization for a target + tier."
    )
    p.add_argument("target", help="URL or hostname")
    p.add_argument("tier", type=int, choices=[0, 1, 2, 3], help="Authorization tier")
    p.add_argument("--create-default", action="store_true",
                   help="Create a template policy file for this host if none exists")
    p.add_argument("--json", action="store_true", dest="as_json",
                   help="Emit JSON result instead of plain text")
    args = p.parse_args()

    host = _host_from_target(args.target)

    if args.create_default:
        _, policy_file = _load_policy(host)
        if policy_file is None:
            written = create_policy(host, args.tier)
            print(f"[+] Template policy created: {written}")
            print(f"    Edit it to set authorized=true, owner_asserted=true, expires, and scope.")

    code, reason, message = check(host, args.tier)
    result = {
        "target": host,
        "tier": args.tier,
        "code": code,
        "reason": reason,
        "message": message,
    }

    if args.as_json:
        print(json.dumps(result))
    elif code == 0:
        print(f"[+] {message}")
    else:
        print(f"[!] BLOCKED ({reason}): {message}", file=sys.stderr)

    return code


if __name__ == "__main__":
    sys.exit(main())
