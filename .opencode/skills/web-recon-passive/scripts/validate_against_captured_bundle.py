"""
validate_against_captured_bundle.py

Offline regression check: replays the analysis layer against a real-world
single-file Vite bundle captured during an earlier assessment. Issues ZERO
network requests — it exists to prove the false-positive filtering works on
production minified output, not on synthetic fixtures.

Expected results (established by manual analysis of this bundle):
  * dangerouslySetInnerHTML / innerHTML  -> 0 in app code (all react-dom internals)
  * http://localhost                     -> not flagged (react-router createURL default)
  * secrets                              -> Web3Forms + Formcarry only, public-by-design
  * react-router 7.13.1, react 19.2.3
  * spa_only = True (gates the RSC/Framework CVEs to non-exploitable)
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import checks  # noqa: E402

BUNDLE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "..", "..", "..", "assets", "index-CJsd0O0e.js")
BUNDLE = os.path.normpath(BUNDLE)
if not os.path.exists(BUNDLE) and len(sys.argv) > 1:
    BUNDLE = sys.argv[1]

text = open(BUNDLE, encoding="utf-8", errors="replace").read()
blobs = {os.path.basename(BUNDLE): text}
ok = fail = 0


def expect(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  ok    {name}")
    else:
        fail += 1
        print(f"  FAIL  {name}  {detail}")


print(f"bundle: {len(text):,} chars (single-file Vite build)\n")
print("=== chunk classification ===")
print("  is_vendor_chunk:", checks.is_vendor_chunk(list(blobs)[0]))
print("  single bundle -> filename separation unavailable; signature filtering used")

print("\n=== SINKS ===")
res = checks.scan_sinks(blobs, checks.SINK_PATTERNS)
for k, v in res.items():
    if v["raw"]:
        print(f"  {k:26} raw={v['raw']:3} filtered={v['filtered_out']:3} app={v['in_app_code']}")
print("  method:", res["dangerouslySetInnerHTML"]["method"][:68])
expect("dangerouslySetInnerHTML: 0 in app code",
       res["dangerouslySetInnerHTML"]["in_app_code"] == 0,
       str(res["dangerouslySetInnerHTML"]["in_app_code"]))
expect("dangerouslySetInnerHTML: raw matches were filtered",
       res["dangerouslySetInnerHTML"]["filtered_out"] >= 10,
       str(res["dangerouslySetInnerHTML"]["filtered_out"]))
expect("innerHTML: 0 in app code (react-dom script-creation filtered)",
       res["innerHTML"]["in_app_code"] == 0, str(res["innerHTML"]["in_app_code"]))
expect("javascript: URI: React's OWN defence is not reported as a sink",
       res["javascript: URI"]["in_app_code"] == 0,
       f"app={res['javascript: URI']['in_app_code']} raw={res['javascript: URI']['raw']}")
expect("method reports the signature-only limitation honestly",
       "signature-only" in res["dangerouslySetInnerHTML"]["method"])

print("\n=== INTERNAL URLS ===")
iu = checks.scan_internal_urls(blobs)
print("  flagged:", [h["match"] for h in iu] or "none")
expect("react-router http://localhost NOT flagged", iu == [], str([h["match"] for h in iu]))

print("\n=== SECRETS / ENDPOINTS ===")
hits = checks.scan_secrets(blobs)
for h in hits:
    tag = "PUBLIC-BY-DESIGN" if h["public_by_design"] else "REAL SECRET"
    print(f"  [{tag}] {h['label']}: {h['match'][:64]}")
real = [h for h in hits if not h["public_by_design"]]
pub = {h["label"] for h in hits if h["public_by_design"]}
expect("no real secrets reported", not real, str([h["label"] for h in real]))
expect("Web3Forms key detected and classed public-by-design",
       "Web3Forms access_key" in pub, str(pub))
expect("Formcarry endpoint detected and classed public-by-design",
       "Formcarry endpoint" in pub, str(pub))

print("\n=== VERSIONS ===")
rr = re.search(r'__reactRouterVersion\s*=\s*"([\d\.]+)"', text)
rv = re.search(r'version["\']?\s*[:=]\s*["\'](1[5-9]\.\d+\.\d+)["\']', text)
print("  react-router:", rr.group(1) if rr else "not found")
print("  react       :", rv.group(1) if rv else "not found")
expect("react-router == 7.13.1", bool(rr) and rr.group(1) == "7.13.1",
       rr.group(1) if rr else "none")
expect("react == 19.2.3", bool(rv) and rv.group(1) == "19.2.3", rv.group(1) if rv else "none")

print("\n=== RSC / SERVER-RUNTIME GATING ===")
rsc = [m for m in checks.RSC_MARKERS if m in text]
srv = [m for m in checks.SERVER_RUNTIME_MARKERS if m in text]
print("  RSC markers    :", rsc or "none")
print("  server runtime :", srv or "none")
print("  spa_only       :", not rsc and not srv)
expect("no RSC markers (gates CVE-2026-53667 to non-exploitable)", not rsc, str(rsc))
expect("no server-runtime markers (gates CVE-2026-42342 / CVE-2026-23869)", not srv, str(srv))
expect("spa_only True", not rsc and not srv)

print("\n=== ROUTES ===")
routes = checks.extract_routes(text)
print(f"  count: {len(routes)}  sample: {routes[:5]}")
expect("client routes extracted", len(routes) >= 10 and "/about-us" in routes, str(routes[:8]))

print("\n=== CONSOLE LOGS (app code only) ===")
logs = []
for p, t in blobs.items():
    if checks.is_vendor_chunk(p):
        continue
    for m in re.finditer(r'console\.(log|debug|info)\s*\(', t):
        s = max(0, m.start() - 160)
        seg = t[s:m.end() + 200]
        if checks._noise(seg):
            continue
        logs.append(seg.replace("\n", " ")[:90])
print(f"  app-code console.* calls: {len(logs)}")
for l in logs[:2]:
    print("   ", l)
expect("exactly the Web3Forms error log survives filtering", len(logs) == 1, str(len(logs)))

print("\n" + "=" * 60)
print(f"  {ok} passed, {fail} failed")
print("=" * 60)
sys.exit(1 if fail else 0)
