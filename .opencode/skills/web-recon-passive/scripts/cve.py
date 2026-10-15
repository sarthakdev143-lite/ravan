"""
cve.py — correlate detected component versions against public advisory data.

Two sources, tried in order:
  1. GitHub Advisory Database REST API, which supports an `affects=pkg@version`
     query and returns exactly the advisories matching a version. Best signal.
  2. NVD keyword search as a fallback.

Both are optional and degrade gracefully: if the network is unavailable or the
API rate-limits you, the scan still completes and simply reports that version
correlation was skipped. Never let an advisory lookup failure kill an assessment.

The important part is NOT the lookup — it is the exploitability judgement that
follows it. A version inside a published range is not automatically vulnerable.
Many framework CVEs are gated on server-side code, specific APIs, or a
deployment mode. This module cross-references the advisory text against what was
actually observed in the target's bundle and reports the distinction explicitly.
"""

import json
import re
import urllib.parse
import urllib.request

GITHUB_ADVISORIES = "https://api.github.com/advisories"
NVD_SEARCH = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = {"User-Agent": "passive-recon/1.0", "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28"}

# Phrases in advisory text that indicate the flaw needs server-side code. When the
# target ships a client-only bundle, these gate real exploitability.
SERVER_GATED = [
    "react server components", "server components", "rsc", "framework mode",
    "server-side", "ssr", "server functions", "@remix-run/server-runtime",
    "@remix-run/node", "@react-router/node", "loader", "action",
    "renderToPipeableStream", "entry.server", "server runtime",
]

# Packages that are server-only by nature.
SERVER_ONLY_PACKAGES = {
    "react-server-dom-webpack", "react-server-dom-turbopack", "react-server-dom-parcel",
    "@react-router/node", "@react-router/express", "@react-router/serve",
    "@remix-run/node", "@remix-run/server-runtime", "@remix-run/express",
    "next", "nuxt", "express", "fastify", "@nestjs/core",
}


def _get(url, timeout=35, headers=None):
    req = urllib.request.Request(url, headers=headers or UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def github_advisories(package, version, ecosystem="npm"):
    """Query GHSA for advisories affecting an exact package@version."""
    q = urllib.parse.urlencode({
        "ecosystem": ecosystem, "affects": f"{package}@{version}",
        "per_page": 25, "type": "reviewed",
    })
    try:
        return _get(f"{GITHUB_ADVISORIES}?{q}")
    except Exception as exc:  # noqa: BLE001
        return {"__error__": f"{type(exc).__name__}: {exc}"}


def nvd_keyword(keyword, limit=8):
    q = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": limit})
    try:
        data = _get(f"{NVD_SEARCH}?{q}", headers={"User-Agent": UA["User-Agent"]})
    except Exception as exc:  # noqa: BLE001
        return {"__error__": f"{type(exc).__name__}: {exc}"}
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        score = severity = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                cd = metrics[key][0].get("cvssData", {})
                score = cd.get("baseScore")
                severity = cd.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                break
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        out.append({"id": cve.get("id"), "score": score, "severity": severity,
                    "published": (cve.get("published") or "")[:10],
                    "description": desc})
    return {"total": data.get("totalResults"), "items": out}


def _version_tuple(v):
    try:
        return tuple(int(x) for x in re.findall(r"\d+", v)[:3])
    except Exception:  # noqa: BLE001
        return (0,)


def assess_exploitability(advisory, bundle_facts):
    """
    Decide whether an advisory that matches by version is plausibly exploitable
    given what was actually observed in the target.

    Returns (verdict, reasoning). verdict in {exploitable, gated, unknown}.
    This is a heuristic aid for the reviewing agent, NOT a substitute for reading
    the advisory. It exists to stop the most common reporting error: listing a
    server-side RSC/SSR CVE as a live finding against a static client-only SPA.
    """
    text = " ".join([
        advisory.get("summary") or "", advisory.get("description") or "",
        json.dumps(advisory.get("vulnerabilities") or [])[:2000],
    ]).lower()

    spa_only = bundle_facts.get("spa_only")
    rsc_markers = bundle_facts.get("rsc_markers") or []
    server_markers = bundle_facts.get("server_runtime_markers") or []

    gated_phrases = [p for p in SERVER_GATED if p in text]
    pkg_names = []
    for v in advisory.get("vulnerabilities") or []:
        p = (v.get("package") or {}).get("name")
        if p:
            pkg_names.append(p.lower())

    server_only_pkg = any(p in SERVER_ONLY_PACKAGES for p in pkg_names)

    reasons = []
    if server_only_pkg:
        reasons.append(f"affects server-only package(s) "
                       f"{[p for p in pkg_names if p in SERVER_ONLY_PACKAGES]} which are "
                       f"absent from the bundle")
    if gated_phrases:
        reasons.append("advisory text is gated on: " + ", ".join(sorted(set(gated_phrases))[:4]))
    if spa_only:
        reasons.append("target ships a client-only bundle — no RSC markers "
                       f"({len(rsc_markers)} found) and no server-runtime markers "
                       f"({len(server_markers)} found)")

    if reasons and spa_only:
        return "gated", ("Version is inside the published range, but exploitation requires "
                         "code this deployment does not ship: " + "; ".join(reasons) +
                         ". Still report it — scanners will flag it, and the protection is "
                         "architectural rather than version-based, so enabling SSR/RSC later "
                         "would make it live with no code change to notice.")
    if reasons:
        return "gated", ("Possible gating factors present (" + "; ".join(reasons) +
                         ") but the bundle does not clearly establish client-only "
                         "deployment. Manual verification required before downgrading.")
    return "exploitable", ("No gating factors identified. Advisory applies to code paths "
                           "that appear present in the target. Treat as live until proven "
                           "otherwise by manual review.")


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def correlate(bundle_facts, timeout_budget=60):
    """
    Look up advisories for every version fingerprint found in the bundle.
    Returns a list of finding dicts consistent with checks.F().
    """
    import time
    from checks import F
    findings = []
    versions = bundle_facts.get("versions") or {}
    if not versions:
        return findings, {"looked_up": [], "note": "no versions fingerprinted"}

    pkg_map = {"react": "react", "react-dom": "react-dom",
               "react-router": "react-router", "vue": "vue", "jquery": "jquery",
               "bootstrap": "bootstrap", "lodash": "lodash", "axios": "axios"}
    looked_up, errors = [], []
    started = time.time()

    for key, ver in versions.items():
        pkg = pkg_map.get(key, key)
        if time.time() - started > timeout_budget:
            errors.append(f"timeout budget exhausted before {pkg}@{ver}")
            break
        adv = github_advisories(pkg, ver)
        if isinstance(adv, dict) and adv.get("__error__"):
            errors.append(f"{pkg}@{ver}: GHSA {adv['__error__']}")
            # fall back to NVD
            nvd = nvd_keyword(f"{pkg} {ver}")
            if isinstance(nvd, dict) and not nvd.get("__error__") and nvd.get("items"):
                looked_up.append({"package": pkg, "version": ver, "source": "nvd",
                                  "count": len(nvd["items"]),
                                  "items": nvd["items"][:5]})
            time.sleep(1)
            continue
        if not isinstance(adv, list):
            continue
        time.sleep(1.2)  # stay well inside unauthenticated rate limits
        if not adv:
            looked_up.append({"package": pkg, "version": ver, "source": "ghsa",
                              "count": 0, "items": []})
            continue
        entries = []
        for a in adv[:8]:
            verdict, reasoning = assess_exploitability(a, bundle_facts)
            sev = (a.get("severity") or "unknown").lower()
            entries.append({
                "id": a.get("cve_id") or a.get("ghsa_id"),
                "ghsa": a.get("ghsa_id"),
                "severity": sev,
                "score": (a.get("cvss") or {}).get("score"),
                "summary": (a.get("summary") or "")[:200],
                "published": (a.get("published_at") or "")[:10],
                "verdict": verdict,
                "reasoning": reasoning,
                "url": a.get("html_url"),
            })
        looked_up.append({"package": pkg, "version": ver, "source": "ghsa",
                          "count": len(adv), "items": entries})

        live = [e for e in entries if e["verdict"] == "exploitable"]
        gated = [e for e in entries if e["verdict"] == "gated"]

        if live:
            worst = max(live, key=lambda e: SEVERITY_RANK.get(e["severity"], 0))
            rank = SEVERITY_RANK.get(worst["severity"], 0)
            sev = {4: "critical", 3: "high", 2: "medium"}.get(rank, "low")
            findings.append(F(
                f"CVE-LIVE-{pkg.upper().replace('-','_')}",
                f"{pkg}@{ver} has {len(live)} advisory match(es) with no gating factors",
                sev, "deps",
                [f"{e['id']} [{e['severity']} {e['score']}] {e['summary']}" for e in live],
                f"Version {ver} of {pkg} is inside the affected range and no gating "
                f"condition was identified from the advisory text or the observed bundle. "
                f"Worst: {worst['id']}.",
                "Depends on the specific advisory. Read each one before assigning impact — "
                "this tool identifies version overlap, not proven exploitability.",
                f"Upgrade {pkg} to the patched release named in each advisory, rebuild, "
                f"and redeploy so the served bundle is actually updated. Add npm audit / "
                f"Dependabot / Snyk to CI with a blocking policy. "
                f"Details: {', '.join(e['url'] or '' for e in live[:3])}",
                exploitable=True))

        if gated:
            findings.append(F(
                f"CVE-GATED-{pkg.upper().replace('-','_')}",
                f"{pkg}@{ver} is inside published CVE range(s) but appears non-exploitable "
                f"as deployed ({len(gated)} match(es))",
                "info", "deps",
                [f"{e['id']} [{e['severity']}] {e['summary']}" for e in gated] +
                [f"gating analysis: {gated[0]['reasoning']}"],
                "The installed version falls within one or more published affected ranges, "
                "but the vulnerable code paths are not present in what this target actually "
                "ships. This distinction was determined by cross-referencing advisory text "
                "against markers found (or absent) in the bundle.",
                "Not currently exploitable. Two caveats: (1) every SCA scanner, npm audit, "
                "Dependabot and commercial assessment WILL report these as findings, so "
                "expect the noise; (2) the protection is architectural, not version-based — "
                "enabling SSR, RSC or a server runtime later makes them live immediately "
                "with no code change that would alert you.",
                f"Upgrade as routine hygiene — usually a one-line bump with no migration "
                f"needed. Then re-run this check. Details: "
                f"{', '.join(e['url'] or '' for e in gated[:3])}",
                exploitable=False))

    return findings, {"looked_up": looked_up, "errors": errors}
