"""KEV + EPSS enrichment for ravan findings. Stdlib only, keyless, cached.

Reads finding JSON (list) from stdin or a file, adds kev/epss fields:
- KEV: CISA catalog (https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv),
  cached 24h in --cache-dir. Offline/missing cache -> kev:false + note.
- EPSS: FIRST API https://api.first.org/data/epss?cve=CVE-... (keyless,
  rate-limited). Offline -> epss:null + note. No threshold is asserted;
  scoring-rubric.md owns prioritization policy.

Usage:
  python scripts/enrich.py findings.json [--cache-dir .cache] [--out enriched.json]
  python scripts/enrich.py --selftest   # offline, no network
"""
import csv
import io
import json
import sys
import time
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
EPSS_URL = "https://api.first.org/data/epss?cve={cve}"
CACHE_TTL = 24 * 3600


def load_kev(cache_dir: Path):
    cache_dir.mkdir(parents=True, exist_ok=True)
    f = cache_dir / "kev.csv"
    if f.exists() and time.time() - f.stat().st_mtime < CACHE_TTL:
        return {r["cveID"] for r in csv.DictReader(io.StringIO(f.read_text()))}
    try:
        req = urllib.request.Request(str(KEV_URL), headers={"User-Agent": "ravan-enrich"})
        data = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")
        f.write_text(data)
        return {r["cveID"] for r in csv.DictReader(io.StringIO(data))}
    except Exception as e:
        if f.exists():
            return {r["cveID"] for r in csv.DictReader(io.StringIO(f.read_text()))}
        raise RuntimeError(f"KEV unavailable offline and no cache: {e}")


def epss_for(cve: str):
    try:
        req = urllib.request.Request(EPSS_URL.format(cve=cve), headers={"User-Agent": "ravan-enrich"})
        raw = urllib.request.urlopen(req, timeout=20).read().decode("utf-8")
        items = json.loads(raw).get("data", [])
        if items:
            return float(items[0].get("epss", 0.0)), float(items[0].get("percentile", 0.0))
    except Exception:
        pass
    return None, None


def enrich(findings, cache_dir: Path, offline=False):
    try:
        kev = set() if offline else load_kev(cache_dir)
        kev_note = None if not offline else "offline: kev unknown"
    except RuntimeError as e:
        kev, kev_note = set(), str(e)
    out = []
    for f in findings:
        f = dict(f)
        cve = f.get("cve") or ""
        f["kev"] = cve in kev if cve else False
        if kev_note:
            f["kev_note"] = kev_note
        if cve and not offline:
            score, pct = epss_for(cve)
            f["epss"], f["epss_percentile"] = score, pct
        else:
            f.setdefault("epss", None)
            f.setdefault("epss_percentile", None)
        f.setdefault("confidence", "medium")
        out.append(f)
    return out


def main(argv):
    if "--selftest" in argv:
        got = enrich([{"id": "T1", "cve": "CVE-2021-44228"}], Path(".cache"), offline=True)
        assert got[0]["kev"] is False and got[0]["epss"] is None
        print("enrich selftest ok (offline)")
        return 0
    src = Path(argv[1]) if len(argv) > 1 and not argv[1].startswith("--") else None
    data = json.loads(src.read_text() if src else sys.stdin.read())
    cache = Path(".cache")
    out = cache / "enriched.json"
    for i, a in enumerate(argv):
        if a == "--cache-dir" and i + 1 < len(argv):
            cache = Path(argv[i + 1])
        if a == "--out" and i + 1 < len(argv):
            out = Path(argv[i + 1])
    res = enrich(data if isinstance(data, list) else [data], cache)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2))
    print(f"enriched {len(res)} findings -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
