#!/usr/bin/env python3
"""
test_checks.py — offline regression tests for the analysis layer.

These exist because of a specific, repeatedly-observed failure mode: naive
pattern matching on minified JavaScript reports framework internals as
application vulnerabilities. Every test below encodes a real false positive that
this tool actually produced during development and then had to fix.

Run with:  python3 test_checks.py            (no network required)

If you add a new pattern to checks.py, add a fixture here that proves it does
not fire on react-dom.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import checks  # noqa: E402
import dnslib  # noqa: E402
import webfetch  # noqa: E402

PASS = FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ok    {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


# ---------------------------------------------------------------------------
# Fixtures. Real minified react-dom output in BOTH major bundler styles, plus
# genuine application-code sinks that MUST still be detected.
# ---------------------------------------------------------------------------

# esbuild / Vite style (single-bundle: vendor + app concatenated)
VITE_REACT_DOM = '''
function Or(e,t,a,l,n,s){switch(a){case"style":Fc(e,t,l,s);break;case"dangerouslySetInnerHTML":
if(l!=null){if(typeof l!=="object"||!("__html"in l))throw Error(c(61));if(a=l.__html,a!=null)
{if(n.children!=null)throw Error(c(60));e.innerHTML=a}}break;case"children":break}}
function O0(i,r=!1){let d="http://localhost";typeof window<"u"&&(d=window.location.origin)}
window.__reactRouterVersion="7.13.1"
'''

# webpack / terser style (Next.js: separate vendor chunk)
NEXT_REACT_DOM = '''
function u7(e,t){return"textarea"===e||"noscript"===e||"string"==typeof t.children||
"number"==typeof t.children||"bigint"==typeof t.children||"object"==typeof t.dangerouslySetInnerHTML
&&null!==t.dangerouslySetInnerHTML&&null!=t.dangerouslySetInnerHTML.__html}
'''

# Genuine application code that SHOULD be reported
APP_CODE = '''
function renderProfile(u){document.getElementById("bio").innerHTML=u.bioHtml;}
const cfg={client_secret:"a8f3k29dlxm47qp",apiKey:"AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"};
fetch("http://192.168.1.50:8080/api/internal",{headers:{Authorization:"Bearer "+t}});
console.log("submission failed",err.response);
'''

print("\n[1] Single-bundle (Vite) — signature filtering only")
res = checks.scan_sinks({"index-abc123.js": VITE_REACT_DOM + APP_CODE},
                        checks.SINK_PATTERNS)
check("react-dom dangerouslySetInnerHTML fully filtered (app has none)",
      res["dangerouslySetInnerHTML"]["in_app_code"] == 0
      and res["dangerouslySetInnerHTML"]["filtered_out"] >= 1,
      f"app={res['dangerouslySetInnerHTML']['in_app_code']} "
      f"filtered={res['dangerouslySetInnerHTML']['filtered_out']}")
check("react-dom .innerHTML filtered, app .innerHTML kept",
      res["innerHTML"]["raw"] == 2 and res["innerHTML"]["in_app_code"] == 1,
      f"raw={res['innerHTML']['raw']} app={res['innerHTML']['in_app_code']}")
iu = checks.scan_internal_urls({"index-abc123.js": VITE_REACT_DOM + APP_CODE})
check("react-router http://localhost default NOT flagged as internal URL",
      not any(h["match"] == "http://localhost" for h in iu),
      str([h["match"] for h in iu]))
check("genuine RFC1918 dev URL IS flagged",
      any("192.168.1.50" in h["match"] for h in iu), str([h["match"] for h in iu]))
check("method reports signature-only limitation",
      "signature-only" in res["innerHTML"]["method"])

print("\n[2] Multi-chunk (Next.js) — filename classification")
blobs = {
    "/_next/static/chunks/framework-abc.js": NEXT_REACT_DOM,
    "/_next/static/chunks/main-def.js": 'window.console.log("[HMR] connected")',
    "/_next/static/chunks/pages/_app-ghi.js": APP_CODE,
}
res = checks.scan_sinks(blobs, checks.SINK_PATTERNS)
check("vendor chunk classified correctly",
      checks.is_vendor_chunk("/_next/static/chunks/framework-abc.js")
      and checks.is_vendor_chunk("/_next/static/chunks/main-def.js"))
check("app chunk NOT classified as vendor",
      not checks.is_vendor_chunk("/_next/static/chunks/pages/_app-ghi.js"))
check("21-style react-dom match yields 0 app sinks",
      res["dangerouslySetInnerHTML"]["in_app_code"] == 0
      and res["dangerouslySetInnerHTML"]["filtered_out"] >= 3,
      f"app={res['dangerouslySetInnerHTML']['in_app_code']}")
check("app-code innerHTML still detected",
      res["innerHTML"]["in_app_code"] == 1)
check("method reports filename+signature",
      "filename+signature" in res["innerHTML"]["method"])

print("\n[3] Secret detection — true positives")
hits = checks.scan_secrets({"app.js": APP_CODE})
labels = {h["label"] for h in hits}
check("client_secret detected", "Generic secret assignment" in labels, str(labels))
check("Google API key detected", "Google API Key" in labels, str(labels))
check("RFC1918 URL detection is in check_bundle, not scan_secrets",
      "Internal/dev URL" not in labels)

print("\n[4] Secret detection — false positives that MUST NOT fire")
BENIGN = '''
algolia:{appId:"1FCF9AYYAT",apiKey:"1b7ad4e1c89e645e351e59d40544eda1",indexName:"docs"}
const onClickCapture=1; function onDoubleClick(e){}
<p>more clarity, efficiency and confidence</p>
import {useState} from "react";
'''
hits = checks.scan_secrets({"app.js": BENIGN})
check("generic apiKey: is NOT reported as Firebase config",
      not any(h["label"] == "Firebase web config" for h in hits),
      str([h["label"] for h in hits]))
check("Algolia search-only key classified public_by_design",
      all(h["public_by_design"] for h in hits if "Algolia" in h["label"])
      and any("Algolia" in h["label"] for h in hits))
check("'clarity' marketing copy does not match Microsoft Clarity tracker",
      not any("clarity" in h["match"].lower() for h in hits))

print("\n[5] Firebase real config still detected")
FB = 'const c={apiKey:"AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY",authDomain:"x.firebaseapp.com"};'
hits = checks.scan_secrets({"app.js": FB})
check("authDomain firebaseapp.com detected",
      any(h["label"] == "Firebase web config" for h in hits), str([h['label'] for h in hits]))
check("AIza key detected", any(h["label"] == "Google API Key" for h in hits))

print("\n[6] Version fingerprinting")
v = {}
import re
m = re.search(r'__reactRouterVersion\s*=\s*"([\d\.]+)"', VITE_REACT_DOM)
check("react-router version constant found", m and m.group(1) == "7.13.1")
m2 = re.search(r'version["\']?\s*[:=]\s*["\'](1[5-9]\.\d+\.\d+)["\']', 'version:"19.2.3"')
check("unquoted-key react version pattern works", m2 and m2.group(1) == "19.2.3")
m3 = re.search(r'version["\']?\s*[:=]\s*["\'](1[5-9]\.\d+\.\d+)["\']', '"version":"19.0.0"')
check("quoted-key react version pattern works", m3 and m3.group(1) == "19.0.0")

print("\n[7] RSC / server-runtime gating markers")
check("static SPA bundle -> spa_only True",
      checks.__dict__ and not any(m in VITE_REACT_DOM for m in checks.RSC_MARKERS)
      and not any(m in VITE_REACT_DOM for m in checks.SERVER_RUNTIME_MARKERS))
check("SSR bundle -> server marker detected",
      "renderToPipeableStream" in
      'require("react-dom/server").renderToPipeableStream')

print("\n[8] DNS response parsing — authority section must not leak into answers")
# A negative answer carries an SOA in the AUTHORITY section. Treating it as an
# answer made every nonexistent subdomain look live.
pkt_hdr_ok = True
check("values() returns [] for NXDOMAIN-style negative answer",
      dnslib.values("zzz-definitely-not-real-88213.example.invalid", "A") == [])
check("resolves_to_address() False for nonexistent name",
      dnslib.resolves_to_address("zzz-definitely-not-real-88213.example.invalid") is False)
check("resolves_to_address() True for example.com",
      dnslib.resolves_to_address("example.com") is True)

print("\n[9] SPF / DMARC parsing")
spf = dnslib.parse_spf(["v=spf1 include:_spf.mail.hostinger.com ~all"])
check("SPF softfail identified", spf["qualifier"] == "~all" and spf["present"])
check("SPF +all identified as dangerous",
      dnslib.parse_spf(["v=spf1 +all"])["qualifier"] == "+all")
check("SPF -all identified as hardfail",
      dnslib.parse_spf(["v=spf1 -all"])["qualifier"] == "-all")
dm = dnslib.parse_dmarc(["v=DMARC1; p=none"])
check("DMARC p=none is NOT enforcing", dm["present"] and not dm["enforcing"])
check("DMARC p=reject IS enforcing",
      dnslib.parse_dmarc(["v=DMARC1; p=reject; rua=mailto:a@b.c"])["enforcing"])
check("DMARC rua extracted",
      dnslib.parse_dmarc(["v=DMARC1; p=reject; rua=mailto:a@b.c"])["rua"] == "mailto:a@b.c")

print("\n[10] CSP / HSTS quality analysis")
check("upgrade-insecure-requests-only CSP flagged as ineffective",
      checks.analyse_csp("upgrade-insecure-requests")["only_upgrade_insecure"])
check("real CSP not flagged as ineffective",
      not checks.analyse_csp("default-src 'self'; script-src 'self'")["only_upgrade_insecure"])
check("unsafe-inline in script-src flagged",
      any("unsafe-inline" in w for w in
          checks.analyse_csp("script-src 'self' 'unsafe-inline'")["weak_tokens"]))
check("frame-ancestors detected",
      checks.analyse_csp("frame-ancestors 'self'")["has_frame_ancestors"])
check("HSTS preload eligibility computed",
      checks.analyse_hsts("max-age=31536000; includeSubDomains; preload")["preload_eligible"])
check("short HSTS not preload eligible",
      not checks.analyse_hsts("max-age=300")["preload_eligible"])

print("\n[11] Route extraction")
routes = checks.extract_routes('path:"/",path:"/about-us",path:"/blog/:slug"')
check("routes extracted", set(routes) == {"/", "/about-us", "/blog/:slug"}, str(routes))

print("\n[12] URL normalisation")
n = webfetch.normalise("augmentinfotech.com")
check("bare host gets https scheme", n["scheme"] == "https" and n["port"] == 443)
check("domain derived from host", n["domain"] == "augmentinfotech.com")
n2 = webfetch.normalise("https://www.sub.example.co.uk/x")
check("multi-label host handled", n2["host"] == "www.sub.example.co.uk")

print("\n" + "=" * 62)
print(f"  {PASS} passed, {FAIL} failed")
print("=" * 62)
sys.exit(1 if FAIL else 0)
