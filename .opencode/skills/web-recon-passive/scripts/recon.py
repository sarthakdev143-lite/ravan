#!/usr/bin/env python3
"""
recon.py — passive external security review of a single web target.

    python3 recon.py --target https://example.com --i-am-authorized \
        --contact you@example.com --out ./report

Pure Python standard library. No pip installs, no browser, no scanner.

WHAT THIS TOOL DOES
  Reads only what an anonymous visitor's browser would read: DNS records from a
  public resolver, TLS certificate data, HTTP response headers and status codes,
  the HTML the page serves, and the JS/CSS bundles that page itself references.

WHAT THIS TOOL REFUSES TO DO
  There is no port scanning, no directory brute-forcing, no fuzzing, no injection
  testing, no authentication attack and no exploitation code anywhere in this
  project — not disabled by a flag, simply absent. A request budget and an
  inter-request delay are enforced so it cannot accidentally generate meaningful
  load. Form endpoints are never POSTed to.

  If you need active testing, use a purpose-built tool (nuclei, nikto, ZAP,
  Burp) under a WRITTEN authorisation with a defined scope. This skill is the
  reconnaissance that tells you where to point those, not a replacement for them.

Exit codes: 0 = completed, 2 = authorization flag missing, 3 = target unreachable,
            1 = unexpected error
"""

import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import checks          # noqa: E402
import cve as cve_mod  # noqa: E402
import dnslib          # noqa: E402
import webfetch        # noqa: E402

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ICON = {"critical": "[!!!!]", "high": "[!!! ]", "medium": "[!!  ]",
        "low": "[!   ]", "info": "[.   ]"}

AUTH_BANNER = """
------------------------------------------------------------------------
 PASSIVE RECONNAISSANCE ONLY

 You asserted authorization for this target. Confirm before continuing:

   * You own or operate {host}, OR you hold written permission to test it.
   * Unauthorised access to computer systems is a criminal offence in most
     jurisdictions (US CFAA, UK CMA 1990, India IT Act 2000 s43/s66, EU
     equivalents). "It was only passive" is not a defence.
   * This tool will make roughly {budget} HTTP(S) requests and a few hundred
     DNS lookups against public resolvers.

 This tool contains no scanning or exploitation capability. It cannot be
 made to attack anything. Findings are indicative, not exhaustive.
------------------------------------------------------------------------
"""


def sort_findings(findings):
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["id"]))


def dedupe(findings):
    seen, out = set(), []
    for f in findings:
        key = (f["id"], f["title"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def run(target_url, contact, dns_server=None, budget=400, delay=0.7,
        do_cve=True, cve_budget=60, follow_redirects=True, extra_paths=None,
        quiet=False):
    def say(msg):
        if not quiet:
            print(msg, flush=True)

    target = webfetch.normalise(target_url)
    say(f"[*] target   : {target['base']}")
    say(f"[*] domain   : {target['domain']}   host: {target['host']}:{target['port']}")

    if not webfetch.resolves(target["host"]):
        say(f"[!] {target['host']} does not resolve — aborting")
        return None, None, 3

    client = webfetch.Client(contact_email=contact, delay=delay, budget=budget)
    findings, facts = [], {}

    # ---------------- 1. DNS ----------------
    say("[*] 1/6  DNS + email authentication")
    f, d = checks.check_dns(target, server=dns_server)
    findings += f
    facts["dns"] = d

    # ---------------- 2. TLS ----------------
    say("[*] 2/6  TLS configuration")
    f, t = checks.check_tls(target)
    findings += f
    facts["tls"] = t

    # ---------------- 3. Homepage ----------------
    say("[*] 3/6  HTTP surface + security headers")
    home = client.get(target["base"] + "/", follow=follow_redirects)
    html_text = ""
    if home.get("body"):
        html_text = home["body"].decode("utf-8", "replace")
    facts["home_status"] = home.get("status")
    facts["home_size"] = home.get("size")
    facts["home_final_url"] = home.get("final_url")

    # HTTP -> HTTPS redirect behaviour
    if target["scheme"] == "https":
        plain = client.get("http://" + target["host"] + "/", follow=False)
        loc = webfetch.Client.header(plain.get("headers"), "Location")
        facts["http_redirect"] = {"status": plain.get("status"), "location": loc}
        if plain.get("status") not in (301, 302, 308):
            findings.append(checks.F(
                "HTTP-NO-REDIRECT", "Plain HTTP is not redirected to HTTPS", "medium",
                "transport", [f"http://{target['host']}/ -> {plain.get('status')}"],
                "Visitors who type the bare domain or follow an http:// link are served "
                "content over cleartext.",
                "Traffic is interceptable and modifiable on-path. Combined with no HSTS "
                "this permits SSL-strip.",
                "Return a 301 to the https:// equivalent, then add HSTS."))

    # www vs apex canonicalisation
    other = "www." + target["domain"] if not target["host"].startswith("www.") else target["domain"]
    canon = client.get(f"{target['scheme']}://{other}/", follow=False)
    facts["canonical_check"] = {"host": other, "status": canon.get("status"),
                                "location": webfetch.Client.header(canon.get("headers"), "Location")}
    if canon.get("status") == 200:
        findings.append(checks.F(
            "HTTP-NO-CANONICAL", f"Both {target['host']} and {other} serve 200 (no canonicalisation)",
            "info", "http", [f"https://{other}/ -> 200 (no redirect)"],
            "Two hostnames serve the same content independently rather than one 301-ing to "
            "the other.",
            "Duplicate content for SEO; cookies and caches are keyed per host; header and "
            "CSP policy can silently diverge between the two. If only one host is covered "
            "by the TLS certificate SANs, one of them may also throw name-mismatch errors.",
            "Pick one canonical host and 301 the other to it. Ensure the certificate covers "
            "both."))

    # error page + platform content
    say("[*]      inspecting platform error page")
    f, e = checks.check_error_page(client, target)
    findings += f
    facts["error_page"] = e

    # header scorecard across the homepage and a deep route
    deep = None
    routes_probe = [p for p in (extra_paths or []) if p != "/"]
    if not routes_probe:
        # derive a deep path from declared routes if we already have the HTML
        prelim = checks.extract_routes(html_text)
        routes_probe = [r for r in prelim if r != "/" and ":" not in r][:1]
    paths = ["/"] + routes_probe
    f, h = checks.check_headers(client, target, extra_paths=tuple(paths))
    findings += f
    facts["headers"] = h

    # ---------------- 4. surface ----------------
    say("[*] 4/6  routing, methods, standards files, source maps")
    asset_paths = sorted(set(
        __import__("re").findall(r'(?:src|href)="(/[^"]+\.(?:js|css|mjs))"', html_text)))
    f, s = checks.check_surface(client, target, html_text, asset_paths)
    findings += f
    facts["surface"] = s

    # ---------------- 5. bundle ----------------
    say("[*] 5/6  client bundle analysis (secrets, sinks, versions)")
    f, b = checks.check_bundle(client, target, html_text)
    findings += f
    facts["bundle"] = b

    # ---------------- 6. CVE correlation ----------------
    if do_cve:
        versions = (b.get("versions") or {})
        if versions:
            say(f"[*] 6/6  advisory correlation for {versions}")
            cf, cdata = cve_mod.correlate(b, timeout_budget=cve_budget)
            findings += cf
            facts["cve"] = cdata
        else:
            say("[*] 6/6  advisory correlation skipped (no versions fingerprinted)")
            facts["cve"] = {"skipped": "no versions fingerprinted"}
    else:
        say("[*] 6/6  advisory correlation skipped (--no-cve)")
        facts["cve"] = {"skipped": "disabled by flag"}

    findings = sort_findings(dedupe(findings))
    facts["meta"] = {
        "target": target["base"], "domain": target["domain"],
        "assessed_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "requests_used": client.used, "request_budget": budget,
        "request_history": client.history,
        "tool": "passive-recon/1.0", "contact": contact,
        "methodology": "passive-only; no scanning, fuzzing, injection or exploitation",
    }
    say(f"[*] done — {len(findings)} findings from {client.used} requests")
    return findings, facts, 0


def write_json(findings, facts, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as fh:
        json.dump({"findings": findings, "facts": facts}, fh, indent=2, default=str)
    return path


def write_markdown(findings, facts, path, target_url):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    meta = facts.get("meta", {})
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    L = []
    A = L.append
    A(f"# Passive Security Review — {meta.get('domain','?')}")
    A("")
    A(f"**Target:** `{meta.get('target', target_url)}`  ")
    A(f"**Assessed:** {meta.get('assessed_at','')}  ")
    A(f"**Method:** {meta.get('methodology','passive')}  ")
    A(f"**Requests issued:** {meta.get('requests_used')} (budget {meta.get('request_budget')})  ")
    A(f"**Contact asserted:** {meta.get('contact')}")
    A("")
    A("## Scope & limitations")
    A("")
    A("Passive review only, using publicly observable information equivalent to what an")
    A("anonymous visitor's browser retrieves. **No** port scanning, directory brute-forcing,")
    A("fuzzing, injection testing, authentication attacks, exploitation, or form submissions.")
    A("Server-side configuration and hosting-account settings were not assessable. The")
    A("absence of a finding is not evidence of security.")
    A("")
    A("## Summary")
    A("")
    A("| Severity | Count |")
    A("|---|---|")
    for sev in ("critical", "high", "medium", "low", "info"):
        A(f"| {sev.title()} | {counts.get(sev,0)} |")
    A(f"| **Total** | **{len(findings)}** |")
    A("")
    A("## Detected stack")
    A("")
    A("| Property | Value |")
    A("|---|---|")
    dns = facts.get("dns", {})
    tls = facts.get("tls", {})
    hdr = facts.get("headers", {})
    bnd = facts.get("bundle", {})
    rows = [
        ("Origin IP", ", ".join(dns.get("a") or []) or "?"),
        ("Nameservers", ", ".join(dns.get("ns") or []) or "?"),
        ("Mail exchangers", ", ".join(dns.get("mx") or []) or "none"),
        ("Server header", hdr.get("server") or "not disclosed"),
        ("TLS protocol", tls.get("protocol") or "?"),
        ("Cert issuer", (tls.get("issuer") or {}).get("organizationName")
         or (tls.get("issuer") or {}).get("commonName") or "?"),
        ("Cert expiry", f"{tls.get('notAfter')} ({tls.get('days_to_expiry','?')} days)"),
        ("Cookies set", "none (stateless)" if hdr.get("stateless") else str(len(hdr.get("cookies") or []))),
        ("Versions", ", ".join(f"{k} {v}" for k, v in (bnd.get("versions") or {}).items()) or "none detected"),
        ("Client-only bundle", "yes" if bnd.get("spa_only") else "no — server markers present"),
        ("External origins", ", ".join((bnd.get("external_origins") or [])[:8]) or "none"),
    ]
    for k, v in rows:
        A(f"| {k} | {v} |")
    A("")
    A("## Findings")
    A("")
    if not findings:
        A("No findings. Re-run with a wider budget or verify the target was reachable.")
    for f in findings:
        A(f"### {ICON[f['severity']]} {f['id']} — {f['title']}")
        A("")
        A(f"**Severity:** {f['severity'].upper()} &nbsp;|&nbsp; **Category:** {f['category']}")
        if f.get("exploitable") is not None:
            A(f" &nbsp;|&nbsp; **Exploitable as deployed:** "
              f"{'YES' if f['exploitable'] else 'NO — version-gated only'}")
        A("")
        A("**Evidence**")
        A("```")
        for ev in f["evidence"][:14]:
            for line in str(ev).splitlines()[:6]:
                A(line[:240])
        A("```")
        A("")
        A(f"**Analysis.** {f['analysis']}")
        A("")
        A(f"**Impact.** {f['impact']}")
        A("")
        A(f"**Remediation.** {f['remediation']}")
        A("")
        A("---")
        A("")

    cve_data = facts.get("cve") or {}
    if cve_data.get("looked_up"):
        A("## Appendix A — Advisory correlation detail")
        A("")
        A("| Package | Version | Source | Matches | Live | Gated |")
        A("|---|---|---|---|---|---|")
        for item in cve_data["looked_up"]:
            live = sum(1 for e in item.get("items", []) if e.get("verdict") == "exploitable")
            gated = sum(1 for e in item.get("items", []) if e.get("verdict") == "gated")
            A(f"| {item['package']} | {item['version']} | {item['source']} | "
              f"{item['count']} | {live} | {gated} |")
        A("")
        for item in cve_data["looked_up"]:
            for e in item.get("items", []):
                A(f"- **{e.get('id')}** [{e.get('severity')}, CVSS {e.get('score')}] "
                  f"{e.get('package','')} — {e.get('summary','')}")
                A(f"  - published {e.get('published')} · verdict: **{e.get('verdict')}**")
                A(f"  - {e.get('reasoning','')}")
                if e.get("url"):
                    A(f"  - {e['url']}")
        A("")
    if cve_data.get("errors"):
        A("**Lookup errors (non-fatal):**")
        for err in cve_data["errors"]:
            A(f"- {err}")
        A("")

    A("## Appendix B — Request log")
    A("")
    A("Every request this tool issued, for transparency and to demonstrate that it stayed")
    A("within passive scope. Review this if you need to show an operator exactly what was")
    A("requested.")
    A("")
    A("| # | Method | URL | Status | Bytes | ms |")
    A("|---|---|---|---|---|---|")
    for i, r in enumerate((meta.get("request_history") or [])[:200], 1):
        url = r.get("url", "")[:90]
        A(f"| {i} | {r.get('method')} | `{url}` | {r.get('status')} | "
          f"{r.get('size','')} | {r.get('elapsed_ms','')} |")
    A("")
    A("*Generated by passive-recon. Findings reflect the target's state at assessment time.*")

    with open(path, "w") as fh:
        fh.write("\n".join(L))
    return path


def main():
    p = argparse.ArgumentParser(
        description="Passive external security review of a single web target.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("--target", "-t", required=True, help="URL or hostname")
    p.add_argument("--i-am-authorized", action="store_true",
                   help="REQUIRED. Asserts you own the target or hold written permission.")
    p.add_argument("--contact", "-c", default="researcher@example.com",
                   help="Contact address put in the User-Agent so operators can reach you")
    p.add_argument("--out", "-o", default="./recon-output", help="Output directory")
    p.add_argument("--dns-server", default=None, help="DNS resolver (default: 1.1.1.1/9.9.9.9/8.8.8.8)")
    p.add_argument("--max-requests", type=int, default=400, help="Hard request budget (default 400)")
    p.add_argument("--delay", type=float, default=0.7, help="Seconds between requests (default 0.7)")
    p.add_argument("--timeout", type=float, default=20, help="Per-request timeout")
    p.add_argument("--no-cve", action="store_true", help="Skip advisory correlation")
    p.add_argument("--cve-timeout", type=int, default=60, help="Advisory lookup time budget")
    p.add_argument("--path", action="append", default=[],
                   help="Extra path(s) to include in the header consistency check (repeatable)")
    p.add_argument("--no-follow", action="store_true", help="Do not follow redirects on the homepage")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--json-only", action="store_true", help="Emit JSON, skip Markdown")
    args = p.parse_args()

    if not args.i_am_authorized:
        print(AUTH_BANNER.replace("{host}", webfetch.normalise(args.target)["host"])
              .replace("{budget}", str(args.max_requests)), file=sys.stderr)
        print("Re-run with --i-am-authorized once you have confirmed the above.\n",
              file=sys.stderr)
        return 2

    os.makedirs(args.out, exist_ok=True)
    stamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    host = webfetch.normalise(args.target)["host"]

    try:
        findings, facts, code = run(
            args.target, contact=args.contact, dns_server=args.dns_server,
            budget=args.max_requests, delay=args.delay, do_cve=not args.no_cve,
            cve_budget=args.cve_timeout, follow_redirects=not args.no_follow,
            extra_paths=args.path or None, quiet=args.quiet)
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        import traceback
        print(f"\n[!] unexpected error: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1

    if code != 0 or findings is None:
        return code or 3

    jpath = os.path.join(args.out, f"{host}-{stamp}.json")
    write_json(findings, facts, jpath)
    print(f"[+] JSON     -> {jpath}")
    if not args.json_only:
        mpath = os.path.join(args.out, f"{host}-{stamp}.md")
        write_markdown(findings, facts, mpath, args.target)
        print(f"[+] Markdown -> {mpath}")

    print("\n=== SEVERITY SUMMARY ===")
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            print(f"  {sev.upper():9} {counts[sev]}")
    print()
    for f in findings:
        print(f"  {ICON[f['severity']]} {f['id']:28} {f['title'][:88]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
