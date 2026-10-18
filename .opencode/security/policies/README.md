# Active-policy directory

One JSON file per target host. Filename = `<host>.json` (e.g. `example.com.json`).

Create with:
```bash
python3 engine/policy_check.py example.com 1 --create-default
```

Then edit the file:
- Set `authorized: true` and `owner_asserted: true` (after confirming ownership with the user)
- Set `expires` to an ISO-8601 timestamp (e.g. `"2026-10-19T23:59:00Z"`)
- Set `tiers.tier1_safe_active.enabled: true` for Nuclei + Semgrep
- Update `scope.included` and `scope.excluded`

The policy is re-validated on every `engine/policy_check.py` call.
Null expiry is invalid for Tier 1+. A past expiry is treated as revoked.
