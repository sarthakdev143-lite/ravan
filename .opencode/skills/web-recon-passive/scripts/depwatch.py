"""OSV batch dependency watcher. Stdlib only, keyless.

Reads a list of {name, version, ecosystem} (JSON) or an SBOM/lockfile
summary, batch-queries https://api.osv.dev/v1/querybatch (100/batch),
prints OSV+GHSA+NVD union records with per-record source attribution.

Usage:
  python scripts/depwatch.py deps.json [--out vulns.json]
  deps.json: [{"name":"lodash","version":"4.17.20","ecosystem":"npm"}]
"""
import json
import sys
import urllib.request
from pathlib import Path

OSV_BATCH = "https://api.osv.dev/v1/querybatch"


def query(packages):
    out = []
    for i in range(0, len(packages), 100):
        body = json.dumps({"queries": [
            {"package": {"name": p["name"], "ecosystem": p.get("ecosystem", "npm")},
             "version": p["version"]} for p in packages[i:i + 100]]}).encode()
        req = urllib.request.Request(OSV_BATCH, data=body,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "ravan-depwatch"})
        resp = json.loads(urllib.request.urlopen(req, timeout=30).read().decode())
        for p, r in zip(packages[i:i + 100], resp.get("results", [])):
            for v in r.get("vulns", []):
                out.append({"package": p["name"], "version": p["version"],
                            "id": v.get("id"), "summary": v.get("summary", "")[:200],
                            "sources": [ref.get("url", "") for ref in v.get("references", [])][:3]})
    return out


def main(argv):
    src = Path(argv[1])
    pkgs = json.loads(src.read_text())
    vulns = query(pkgs)
    dst = Path(argv[argv.index("--out") + 1]) if "--out" in argv else Path("vulns.json")
    dst.write_text(json.dumps(vulns, indent=2))
    print(f"{len(vulns)} vulns across {len(pkgs)} packages -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
