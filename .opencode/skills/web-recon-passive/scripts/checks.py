"""
checks.py — the actual assessment logic. Each check_* function returns a list of
finding dicts. Findings are declarative data, not prose, so the calling agent can
reason over them, re-rank them, and write its own report.

Severity scale used here:
  critical  exploitable now, leads to compromise or data loss
  high      exploitable now with real business impact
  medium    meaningfully weakens a control, or exploitable with preconditions
  low       hardening gap / defence-in-depth / hygiene
  info      context, no action strictly required

A note on the discipline that matters most in this file: MINIFIED JS IS NOT
APPLICATION CODE. Naively grepping a production bundle for `innerHTML`,
`dangerouslySetInnerHTML`, `eval(` or `http://localhost` will "find" dozens of
matches that are actually react-dom / react-router internals, or the word
"clarity" in marketing copy, or React's `onDoubleClick` event name. Every
context-sensitive pattern below runs through LIBRARY_NOISE filtering before it
becomes a finding. Skipping that step produces reports that are embarrassing.
"""

import json
import re
import ssl
import socket
import urllib.parse

import dnslib
import webfetch

# Signatures that identify minified framework internals rather than app code.
# NOTE: these are minifier-specific. Vite/esbuild and Next.js/webpack emit
# DIFFERENT output for the same react-dom source, so a signature list tuned on
# one bundler leaks false positives on the other. That is why filename-based
# vendor classification (below) is the primary mechanism, and these signatures
# are only the fallback for single-bundle builds where vendor and app code are
# concatenated into one file and cannot be separated by name.
LIBRARY_NOISE = [
    # esbuild / Vite style
    "Error(c(", "Error(i(", "react.dev/errors", "__REACT_DEVTOOLS_GLOBAL_HOOK__",
    'case"dangerouslySetInnerHTML"', "checkDCE", "unstable_forceFrameRate",
    'process.emit("uncaughtException"', "must be used inside a RouteContext",
    "must be used within a data router", "picking-a-router", "onDoubleClickCapture",
    "React Router caught the following error", "Error handled by React Router",
    # webpack / terser style (Next.js and similar)
    '"textarea"===e||"noscript"===e', '"noscript"===e', "typeof t.children",
    "__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED", "Minified React error",
    "reactjs.org/link", "Invalid hook call", "[HMR] connected", "__NEXT_HMR",
    # react-router's createURL helper legitimately defaults its base to
    # http://localhost. Without these signatures a single-bundle Vite build
    # reports it as a leaked internal/dev URL. (Caught by the test suite.)
    "No window.location.(origin|href) available to create URL", "createHref",
    "encodeLocation", "available to create URL",
    # react-dom's <script> element creation uses innerHTML deliberately.
    "createElementNS", 'innerHTML="<script>',
    # CRITICAL: these are React's own XSS DEFENCES, not vulnerabilities.
    # `ci()` rewrites javascript: URLs to a throwing stub, and the form-action
    # guard does the same. Reporting them as findings would invert the meaning
    # of the result entirely. (Caught by validating against a real bundle.)
    "React has blocked a javascript: URL as a security precaution",
    "A React form was unexpectedly submitted", "requestSubmit",
]

# Filename patterns identifying vendor/framework chunks. Pattern matches found
# only in these files are library internals and must not become findings.
VENDOR_CHUNK_RE = re.compile(
    r"(?:^|/)(?:framework|react-dom|vendor|chunk-vendors|polyfills|webpack|runtime|"
    r"main|libs?|commons?)[-.]", re.I)


def is_vendor_chunk(path: str) -> bool:
    """Classify a bundle path as vendor/framework vs application code."""
    name = path.rsplit("/", 1)[-1]
    return bool(VENDOR_CHUNK_RE.search(name))

SECRET_PATTERNS = {
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9/+=]{40}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe secret key": r"sk_(live|test)_[0-9a-zA-Z]{16,}",
    "Stripe publishable key": r"pk_(live|test)_[0-9a-zA-Z]{16,}",
    "Slack token": r"xox[baprs]-[0-9A-Za-z-]{10,}",
    "GitHub token": r"gh[pousr]_[0-9A-Za-z]{32,}",
    "GitLab token": r"glpat-[0-9A-Za-z\-_]{20,}",
    "SendGrid API key": r"SG\.[0-9A-Za-z\-_]{16,}\.[0-9A-Za-z\-_]{16,}",
    "Twilio API key": r"SK[0-9a-fA-F]{32}",
    "Mailgun key": r"key-[0-9a-zA-Z]{32}",
    "OpenAI key": r"sk-(proj-)?[A-Za-z0-9_\-]{20,}",
    "Anthropic key": r"sk-ant-[A-Za-z0-9_\-]{20,}",
    "Private key block": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    "JSON Web Token": r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,}",
    "Supabase URL + anon key": r"[a-z0-9]{16,}\.supabase\.co",
    # Firebase web keys are always AIza-prefixed; a bare `apiKey:` property is far
    # too generic (Algolia, maps, analytics all use it) and produced false
    # positives. Require Firebase-specific sibling keys in the same object.
    "Firebase web config": r"(?i)authDomain\s*:\s*[\"'][^\"']+\.firebaseapp\.com[\"']",
    "Realtime DB URL": r"[\"'][a-z0-9\-]+\.firebaseio\.com[\"']",
    # Algolia search-only keys are public BY DESIGN — listed separately so they
    # are reported as informational context, never as a critical leak.
    "Algolia search-only key": r"(?i)algolia[^}]{0,160}?apiKey\s*:\s*[\"'][0-9a-f]{32}[\"']",
    "Razorpay key": r"rzp_(live|test)_[0-9A-Za-z]{8,}",
    "Basic auth in URL": r"https?://[^/\s:@\"]{2,}:[^/\s:@\"]{2,}@",
    "Web3Forms access_key": r"access_key[\"']?\s*,?\s*[\"']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "Formcarry endpoint": r"formcarry\.com/s/[A-Za-z0-9_\-]+",
    "Formspree endpoint": r"formspree\.io/f/[A-Za-z0-9]+",
    "Generic secret assignment": r"(?i)[\"']?(client_secret|api_secret|app_secret|private_key|db_password|database_url)[\"']?\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']",
}

# Third-party keys/endpoints that are *designed* to be embedded client-side.
# Reported as "abusable endpoint", NOT "leaked credential" — the distinction
# changes both severity and remediation. Mislabelling these as critical secrets
# is one of the most common ways automated reports lose credibility.
PUBLIC_BY_DESIGN = ("Web3Forms access_key", "Formcarry endpoint", "Formspree endpoint",
                    "Algolia search-only key", "Stripe publishable key")

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "medium",
     "Forces HTTPS on repeat visits; blocks SSL-strip/downgrade on first load."),
    ("X-Content-Type-Options", "low",
     "Should be 'nosniff'; prevents MIME-type sniffing script execution."),
    ("Content-Security-Policy", "low",
     "Restricts script/style/frame/connect sources; primary XSS defence-in-depth."),
    ("X-Frame-Options", "medium",
     "Clickjacking defence (legacy; CSP frame-ancestors is the modern control)."),
    ("Referrer-Policy", "low",
     "Limits URL/query-string leakage to third-party origins you link to."),
    ("Permissions-Policy", "low",
     "Disables unused browser features (camera, mic, geolocation, payment)."),
    ("Cross-Origin-Opener-Policy", "low",
     "Isolates the browsing context group; blocks cross-window attacks."),
    ("Cross-Origin-Resource-Policy", "low",
     "Controls which origins may embed your resources."),
    ("Cross-Origin-Embedder-Policy", "info",
     "Enables cross-origin isolation; often intentionally omitted."),
]

DISCLOSURE_HEADERS = ["platform", "panel", "x-powered-by", "x-aspnet-version",
                      "x-generator", "x-drupal-cache", "x-runtime", "x-vercel-id"]

STANDARDS_FILES = [
    ("/robots.txt", "Crawler directives"),
    ("/sitemap.xml", "Crawler route list"),
    ("/.well-known/security.txt", "RFC 9116 vulnerability disclosure contact"),
    ("/security.txt", "Disclosure contact (legacy location)"),
    ("/humans.txt", "Attribution"),
    ("/favicon.ico", "Browser default request"),
]

RSC_MARKERS = ["RSCErrorHandler", "unstable_RSC", "createRSCHandler", "rscPayload",
               "RSCRequest", "createCallServer", "unstable_createCallServer",
               "FlightClient", "ServerFunction", "__reactRouterRSC"]

SERVER_RUNTIME_MARKERS = ["createRequestHandler", "@react-router/node",
                          "@react-router/express", "@react-router/serve",
                          "entry.server", "renderToPipeableStream",
                          "remix-run/server-runtime", "@remix-run/node"]


def F(fid, title, severity, category, evidence, analysis, impact, remediation,
      exploitable=None, cvss=None, kev=False, epss=None, confidence="medium",
      verdict=None):
    """Construct a finding dict.

    Scoring fields (see references/scoring-rubric.md): cvss vector/score,
    kev membership, epss percentile, confidence high/medium/low, and the
    exploitable/gated verdict. Defaults keep old call sites working.
    """
    return {"id": fid, "title": title, "severity": severity, "category": category,
            "evidence": evidence if isinstance(evidence, list) else [str(evidence)],
            "analysis": analysis, "impact": impact, "remediation": remediation,
            "exploitable": exploitable, "cvss": cvss, "kev": kev, "epss": epss,
            "confidence": confidence,
            "verdict": verdict if verdict is not None else (
                "exploitable" if exploitable else ("gated" if exploitable is False else None))}


def _noise(segment: str) -> bool:
    return any(sig in segment for sig in LIBRARY_NOISE)


# ===========================================================================
# 1. DNS + email authentication
# ===========================================================================
def check_dns(target, server=None):
    findings, facts = [], {}
    domain = target["domain"]
    host = target["host"]
    facts["domain"] = domain

    a = dnslib.values(domain, "A", server=server)
    aaaa = dnslib.values(domain, "AAAA", server=server)
    facts["a"] = a
    facts["aaaa"] = aaaa
    facts["ns"] = dnslib.values(domain, "NS", server=server)
    facts["mx"] = dnslib.values(domain, "MX", server=server)
    # RFC 7505 "null MX" (0 .) declares the domain accepts no mail at all.
    # Inbound-mail findings (DKIM, MTA-STS, TLS-RPT) are then irrelevant, but
    # sender-side spoofing findings (SPF, DMARC) still matter: a domain that
    # cannot RECEIVE mail can still be forged as a SENDER.
    facts["null_mx"] = any(v.strip() == "0 ." for v in facts["mx"])
    facts["accepts_mail"] = bool(facts["mx"]) and not facts["null_mx"]

    # ---- SPF ----
    txt = dnslib.values(domain, "TXT", server=server)
    facts["txt"] = txt
    spf = dnslib.parse_spf(txt)
    facts["spf"] = spf
    if not spf["present"]:
        findings.append(F(
            "DNS-SPF-MISSING", "No SPF record published", "high", "email",
            [f"dig TXT {domain} -> {txt or 'no TXT records'}"],
            "Without an SPF record, receiving servers have no way to determine which "
            "hosts are permitted to send mail for this domain.",
            "Any host can send mail claiming to be from this domain. Enables spoofing, "
            "phishing and invoice fraud against clients and staff.",
            f'Publish: {domain}. TXT "v=spf1 include:<provider> -all" — enumerate every '
            "legitimate sender first."))
    elif spf["qualifier"] == "+all":
        findings.append(F(
            "DNS-SPF-PERMISSIVE", "SPF ends in +all (permits any sender)", "critical", "email",
            [spf["record"]],
            "The '+all' mechanism explicitly authorises every host on the internet to "
            "send mail for this domain, making SPF worse than useless.",
            "SPF provides no protection whatsoever and may actively signal to receivers "
            "that any sender is legitimate.",
            "Change the trailing mechanism to '-all' (hardfail) or '~all' at minimum."))
    elif spf["qualifier"] == "~all":
        findings.append(F(
            "DNS-SPF-SOFTFAIL", "SPF uses ~all (softfail) rather than -all", "low", "email",
            [spf["record"], f"qualifier: {spf['qualifier']} -> {spf['strength']}"],
            "Softfail is advisory: receivers are told a mismatch is suspicious but are "
            "not required to reject the message. Acceptable as a transitional state while "
            "you are still enumerating senders, but not a target state.",
            "Spoofed mail that fails SPF can still reach inboxes, typically landing in "
            "spam rather than being rejected.",
            "Once DKIM is live and all senders are enumerated, move to '-all'. Do not "
            "switch early or legitimate mail will be dropped."))
    if spf.get("ptr_used"):
        findings.append(F(
            "DNS-SPF-PTR", "SPF uses the deprecated 'ptr' mechanism", "low", "email",
            [spf["record"]],
            "RFC 7208 deprecates 'ptr' — it is slow, unreliable and easily spoofed.",
            "Mail delivery failures and weaker authentication.",
            "Remove 'ptr' and enumerate senders with 'ip4:'/'include:' explicitly."))

    # ---- DMARC ----
    dmarc = dnslib.parse_dmarc(dnslib.values(f"_dmarc.{domain}", "TXT", server=server))
    facts["dmarc"] = dmarc
    if not dmarc["present"]:
        findings.append(F(
            "DNS-DMARC-MISSING", "No DMARC record published", "high", "email",
            [f"dig TXT _dmarc.{domain} -> NXDOMAIN"],
            "DMARC tells receiving servers what to do when SPF and/or DKIM fail. "
            "Without it, there is no domain-level policy at all.",
            "Complete freedom to spoof this domain. Combined with missing or "
            "non-enforcing SPF/DKIM, phishing mail will be delivered normally.",
            f'Publish: _dmarc.{domain}. TXT "v=DMARC1; p=none; '
            f'rua=mailto:dmarc@{domain}" to begin collecting reports, then move to '
            "p=quarantine and finally p=reject."))
    elif not dmarc["enforcing"]:
        findings.append(F(
            "DNS-DMARC-NONE", f"DMARC policy is p={dmarc['policy']} (monitoring only)",
            "high", "email",
            [dmarc["record"], f"policy: p={dmarc['policy']}",
             f"reporting: {dmarc['reporting'] or 'none configured'}",
             f"subdomain policy: {dmarc['subdomain_policy']}"],
            "p=none is a reporting-only policy. It instructs receivers to take no action "
            "on failing mail — it does not quarantine or reject anything. This is the "
            "correct *starting* point while collecting data, but it is not protection.",
            "An attacker can send mail appearing to originate from any address at this "
            "domain and it will be delivered rather than rejected. For a business, this "
            "enables invoice/payment fraud against clients, fake recruitment or job-offer "
            "scams targeting candidates, credential phishing against staff, and "
            "reputational damage plus degraded deliverability for legitimate mail.",
            "Progress through: (1) p=none with rua= reporting for 2-4 weeks and review "
            "the XML reports for legitimate senders you missed; (2) p=quarantine pct=100; "
            "(3) p=reject. Add adkim=s aspf=s for strict alignment. Also set an explicit "
            "sp= policy so subdomains are covered."))
    if dmarc["present"] and dmarc["enforcing"]:
        facts["dmarc_enforcing"] = True
    if facts.get("null_mx") and not dmarc.get("enforcing"):
        findings.append(F(
            "DNS-NULLMX-NO-DMARC",
            "Domain publishes a null MX but DMARC does not enforce", "high", "email",
            [f"MX: {facts['mx']} (RFC 7505 null MX — accepts no inbound mail)",
             f"DMARC: {dmarc.get('record', 'absent')}"],
            "A null MX correctly declares that the domain receives no mail, so inbound-"
            "focused controls (DKIM, MTA-STS, TLS-RPT) are genuinely unnecessary and are "
            "correctly not reported. However the domain can still be forged as a SENDER, "
            "and a non-enforcing DMARC policy does nothing to stop that.",
            "Attackers can send mail appearing to come from this domain. Because the "
            "domain legitimately receives nothing, recipients who try to reply get "
            "bounces — which is itself a useful signal to a victim that something is wrong, "
            "but does not prevent the initial deception.",
            "This is the easy case: since no legitimate mail is ever sent either, you can "
            f'go straight to a reject-all posture. Publish _dmarc.{domain}. TXT '
            '"v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@<elsewhere>" and an SPF '
            f'record of "{domain}. TXT v=spf1 -all" (empty sender set).'))
    if dmarc["present"] and not dmarc["reporting"]:
        findings.append(F(
            "DNS-DMARC-NOREPORT", "DMARC has no rua/ruf reporting address", "low", "email",
            [dmarc["record"]],
            "Without rua= you receive no aggregate reports, so you cannot see who is "
            "sending as your domain and cannot safely tighten the policy.",
            "You are blind to spoofing attempts, and any move to quarantine/reject risks "
            "breaking a legitimate sender you did not know about.",
            f'Add rua=mailto:dmarc@{domain} (create the mailbox first) or use a free '
            "DMARC report processor."))

    # ---- DKIM ----
    dkim_found = []
    for selector in dnslib.COMMON_DKIM_SELECTORS:
        recs = dnslib.values(f"{selector}._domainkey.{domain}", "TXT", server=server)
        if recs:
            dkim_found.append((selector, recs[0][:90]))
    facts["dkim"] = dkim_found
    if not dkim_found and facts["accepts_mail"]:
        findings.append(F(
            "DNS-DKIM-MISSING",
            "No DKIM public key found on any common selector", "high", "email",
            [f"MX present: {facts['mx']} (domain does send/receive mail)",
             f"swept {len(dnslib.COMMON_DKIM_SELECTORS)} selectors "
             f"(default, google, hostinger, mail, smtp, s1, s2, k1, selector1, ...) -> 0 records"],
            "The domain has working mail exchangers but publishes no DKIM public key on "
            "any standard selector. Note this is an inference from a bounded selector "
            "sweep, not proof — a provider could use a selector outside this list. "
            "Verify in your mail provider's console.",
            "Without a DKIM signature, DMARC has nothing to align against for mail sent "
            "from the legitimate platform, and spoofed mail cannot be distinguished by "
            "signature. This is the single highest-impact weakness in the email posture.",
            "Enable DKIM in your hosting/mail control panel (for Hostinger: hPanel -> "
            "Emails -> your domain -> DNS settings). It generates the TXT record for you. "
            f"Verify with: dig TXT <selector>._domainkey.{domain} +short"))
    elif dkim_found:
        facts["dkim_ok"] = True

    # ---- CAA ----
    caa = dnslib.values(domain, "CAA", server=server)
    facts["caa"] = caa
    if not caa:
        findings.append(F(
            "DNS-CAA-MISSING", "No CAA record — any CA may issue certificates", "low", "infra",
            [f"dig CAA {domain} -> NOERROR with 0 answers"],
            "CAA restricts which certificate authorities may issue for a domain. With no "
            "record, every CA is permitted.",
            "If an attacker can satisfy any CA's domain-validation checks — via a "
            "subdomain takeover, DNS misconfiguration, mailbox compromise, or CA "
            "misissuance — nothing in DNS prevents a browser-trusted certificate being "
            "issued for this domain.",
            f'Publish: {domain}. CAA 0 issue "letsencrypt.org" (plus issuewild), and '
            f'CAA 0 iodef "mailto:security@{domain}" after creating that mailbox. '
            "If you later front the site with a CDN/WAF, add that provider's CA too or "
            "renewals will fail."))

    # ---- DNSSEC ----
    dnskey = dnslib.query(domain, "DNSKEY", server=server, dnssec=True)
    ds = dnslib.values(domain, "DS", server=server)
    facts["dnssec"] = bool(dnskey.get("answers")) or bool(ds)
    if not facts["dnssec"]:
        findings.append(F(
            "DNS-DNSSEC-MISSING", "Zone is not DNSSEC-signed", "low", "infra",
            [f"dig DNSKEY {domain} -> 0 answers", f"dig DS {domain} -> {ds or 'none'}"],
            "DNS responses are not cryptographically signed, so a spoofed or "
            "cache-poisoned resolution path can return attacker-chosen addresses without "
            "any detectable inconsistency.",
            "On-path attackers can redirect traffic. Also blocks DANE, which would "
            "otherwise let you pin the mail TLS certificate in DNS.",
            "Enable DNSSEC in your hosting panel (Hostinger: hPanel -> Domains -> DNSSEC) "
            "then publish the DS record at the registrar. Verify at https://dnsviz.net."))

    # ---- MTA-STS / TLS-RPT ----
    mtasts = dnslib.values(f"_mta-sts.{domain}", "TXT", server=server)
    tlsrpt = dnslib.values(f"_smtp._tls.{domain}", "TXT", server=server)
    facts["mta_sts"] = mtasts
    facts["tls_rpt"] = tlsrpt
    if facts["accepts_mail"] and not mtasts and not tlsrpt:
        findings.append(F(
            "DNS-MTASTS-MISSING", "No MTA-STS or SMTP TLS reporting", "low", "email",
            [f"MX: {facts['mx']}", f"_mta-sts TXT -> {mtasts or 'none'}",
             f"_smtp._tls TXT -> {tlsrpt or 'none'}"],
            "SMTP encrypts opportunistically: an on-path attacker can strip STARTTLS and "
            "downgrade to cleartext without either side noticing. MTA-STS (RFC 8461) lets "
            "you declare that TLS is mandatory; TLS-RPT (RFC 8460) tells you when it fails.",
            "Inbound and outbound mail can silently fall back to unencrypted transport, "
            "exposing message content to network observers.",
            f'Publish _mta-sts.{domain}. TXT "v=STSv1; id=<timestamp>;", point '
            f"mta-sts.{domain} at a host serving /.well-known/mta-sts.txt listing your MX "
            'hosts with mode: enforce, and add _smtp._tls TXT "v=TLSRPTv1; '
            f'rua=mailto:tlsrpt@{domain}". Do this after DNSSEC is live.'))

    # ---- wildcard detection (must run before any subdomain enumeration) ----
    wildcard, wc_evidence = dnslib.detect_wildcard(domain, server=server)
    facts["wildcard_dns"] = wildcard
    if wildcard:
        facts["wildcard_evidence"] = wc_evidence

    # ---- dangling / interesting subdomains (bounded, passive) ----
    interesting = []
    for sub in ["ftp", "sftp", "cpanel", "webmail", "admin", "dev", "staging",
                "test", "beta", "old", "backup", "phpmyadmin", "mail"]:
        name = f"{sub}.{domain}"
        # Use a real existence check. A plain TXT/A lookup returning data is not
        # enough: negative answers carry an SOA in the authority section, and a
        # CNAME chain can look like a resolution.
        if not (dnslib.resolves_to_address(name, "A", server=server)
                or dnslib.resolves_to_address(name, "AAAA", server=server)):
            continue
        cname = dnslib.cname_target(name, server=server)
        addrs = dnslib.values(name, "A", server=server)
        interesting.append((name, cname or (addrs[0] if addrs else "?")))
    facts["subdomains"] = interesting

    if wildcard:
        findings.append(F(
            "DNS-WILDCARD", f"Zone uses wildcard DNS — subdomain findings suppressed",
            "info", "infra",
            [f"probe {wc_evidence} resolves, so *.{domain} is a catch-all",
             f"{len(interesting)} common subdomain name(s) also resolve, which proves "
             f"nothing under a wildcard"],
            "Every name under this domain resolves to the same target. That is normal for "
            "platforms such as Cloudflare, Vercel, Heroku and parked domains, and for "
            "catch-all configurations.",
            "No direct security impact, but it invalidates a whole class of finding. "
            "Under a wildcard, admin/dev/staging/phpmyadmin hostnames appear to exist "
            "when they do not, so reporting them would be pure noise. Conversely, a "
            "wildcard can itself enable subdomain takeover if it points at a "
            "deprovisioned third-party service.",
            "If the wildcard points to a third-party service you no longer use, remove it "
            "— that is a takeover vector. Otherwise no action; this note exists to explain "
            "why no subdomain findings are listed."))
    for name, value in interesting:
        if wildcard:
            break
        low = name.lower()
        if low.startswith("ftp."):
            findings.append(F(
                "DNS-FTP-HOST", f"{name} resolves to {value}", "info", "infra",
                [f"{name} -> {value}"],
                "An FTP hostname exists. Plain FTP transmits credentials and file content "
                "in cleartext, and an FTP account with write access to the web root is a "
                "direct path to arbitrary code execution on the site. No port scan was "
                "performed — this only confirms the DNS record exists.",
                "If FTP is enabled, credentials may be sniffable and the web root may be "
                "writable by a weak credential.",
                "Verify in your hosting panel whether FTP is enabled. Prefer SFTP or the "
                "panel file manager / Git deployment. If FTP is not in use, delete the DNS "
                "record — a dangling record pointing at your origin invites probing."))
        elif any(k in low for k in ("admin", "cpanel", "phpmyadmin", "webmail")):
            findings.append(F(
                "DNS-ADMIN-HOST", f"Administrative hostname {name} resolves", "info", "infra",
                [f"{name} -> {value}"],
                "An administrative interface hostname is published in DNS. This does not "
                "mean it is reachable or weakly protected — it was not probed — but it "
                "narrows an attacker's search considerably.",
                "Admin panels are high-value targets for credential guessing and for "
                "exploits in the panel software itself.",
                "Confirm the panel is not internet-facing, or restrict it by IP allowlist "
                "and require MFA. If unused, remove the record."))
        elif any(k in low for k in ("dev", "staging", "test", "beta", "old", "backup")):
            findings.append(F(
                "DNS-NONPROD-HOST", f"Non-production hostname {name} resolves", "info", "infra",
                [f"{name} -> {value}"],
                "A development, staging or backup host is publicly resolvable. Non-prod "
                "environments routinely run weaker controls than production: debug modes, "
                "default credentials, test data, older dependency versions.",
                "Non-production systems are a common entry point that bypasses the "
                "hardened production perimeter.",
                "Confirm it is not publicly reachable, or place it behind authentication "
                "and an IP allowlist. Remove the record if it is stale."))

    # ---- IPv6 ----
    if not aaaa and a:
        findings.append(F(
            "DNS-NO-IPV6", "No AAAA record — site is IPv4-only", "info", "infra",
            [f"A: {a}", "AAAA: 0 answers"],
            "The domain publishes no IPv6 address.",
            "Not a security issue. Affects reachability for IPv6-only networks and is a "
            "minor SEO/accessibility consideration.",
            "Optional: enable IPv6 if your host supports it."))

    return findings, facts


# ===========================================================================
# 2. TLS
# ===========================================================================
def check_tls(target):
    findings, facts = [], {}
    host, port = target["host"], target["port"]
    if target["scheme"] != "https":
        return [F("TLS-PLAIN", "Target is HTTP-only", "high", "transport",
                  [f"{target['base']}"], "No TLS in use.",
                  "All traffic is cleartext and trivially intercepted.",
                  "Obtain a certificate (Let's Encrypt is free) and redirect HTTP to HTTPS.")], facts

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                facts["protocol"] = tls.version()
                facts["cipher"] = tls.cipher()
    except ssl.SSLCertVerificationError as exc:
        findings.append(F(
            "TLS-INVALID-CERT", "Certificate does not validate", "critical", "transport",
            [str(exc)], "The certificate failed chain/hostname validation.",
            "Browsers show a full-page warning; users are trained to click through, and "
            "the connection is not authenticated.",
            "Renew or reissue the certificate with correct SAN coverage."))
        return findings, facts
    except Exception as exc:  # noqa: BLE001
        findings.append(F(
            "TLS-UNREACHABLE", f"TLS handshake failed: {type(exc).__name__}", "high",
            "transport", [str(exc)], "Could not complete a TLS handshake.",
            "The HTTPS endpoint may be broken or firewalled.",
            "Investigate server configuration and certificate installation."))
        return findings, facts

    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
    facts.update({"subject": subject, "issuer": issuer, "sans": sans,
                  "notBefore": cert.get("notBefore"), "notAfter": cert.get("notAfter")})

    # expiry
    import datetime
    try:
        expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days = (expiry - datetime.datetime.utcnow()).days
        facts["days_to_expiry"] = days
        if days < 0:
            findings.append(F("TLS-EXPIRED", "Certificate has expired", "critical",
                              "transport", [f"expired {abs(days)} days ago"],
                              "The certificate is past its notAfter date.",
                              "Hard browser errors for every visitor.",
                              "Renew immediately and fix automation."))
        elif days < 15:
            findings.append(F(
                "TLS-EXPIRING", f"Certificate expires in {days} days", "high", "transport",
                [f"notAfter: {cert['notAfter']}"], "Renewal is imminent.",
                "Imminent full outage of HTTPS if auto-renewal is broken.",
                "Verify auto-renewal is functioning (certbot renew --dry-run or the "
                "hosting panel's SSL page)."))
    except Exception:  # noqa: BLE001
        pass

    # SAN coverage of www vs apex
    domain = target["domain"]
    want = {domain, f"www.{domain}"}
    missing = want - set(sans)
    if missing:
        findings.append(F(
            "TLS-SAN-GAPS", f"Certificate does not cover: {sorted(missing)}", "medium",
            "transport", [f"SANs: {sans}"],
            "Some valid hostnames for this site are not covered by the certificate.",
            "Name-mismatch errors for visitors using the uncovered hostname.",
            "Reissue including all served hostnames, or redirect uncovered names to a "
            "covered canonical host."))

    # weak protocols — Python removed the per-version PROTOCOL_* constants, so
    # pin minimum_version/maximum_version instead to test each in isolation.
    weak = []
    client_unsupported = []
    for label, ver in [("TLSv1.0", ssl.TLSVersion.TLSv1),
                       ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.minimum_version = ver
            c.maximum_version = ver
        except (ValueError, AttributeError):
            # Local OpenSSL refuses to even offer this version. That is a client
            # limitation, NOT evidence the server rejects it. Record honestly.
            client_unsupported.append(label)
            continue
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with c.wrap_socket(sock, server_hostname=host) as tls:
                    weak.append(f"{label} accepted ({tls.version()} {tls.cipher()[0]})")
        except Exception:  # noqa: BLE001 - rejection is the good outcome
            pass
    facts["weak_protocols"] = weak
    facts["tls_untestable_locally"] = client_unsupported
    if weak:
        findings.append(F(
            "TLS-LEGACY-PROTO", "Deprecated TLS protocol versions accepted", "high",
            "transport", weak + [f"current negotiation: {facts.get('protocol')}"],
            "The server still negotiates TLS 1.0 and/or 1.1, both deprecated by RFC 8996 "
            "and vulnerable to BEAST/POODLE-class downgrade attacks.",
            "An on-path attacker can force a downgrade to a broken protocol. Also fails "
            "PCI-DSS and most compliance scans.",
            "Set the server's minimum protocol to TLS 1.2. On LiteSpeed/Apache: "
            "SSLProtocol -all +TLSv1.2 +TLSv1.3"))
    else:
        facts["tls_ok"] = True
        if client_unsupported:
            findings.append(F(
                "TLS-LEGACY-INCONCLUSIVE",
                f"Could not test {', '.join(client_unsupported)} from this machine",
                "info", "transport",
                [f"local OpenSSL refused to offer: {client_unsupported}",
                 f"negotiated by default: {facts.get('protocol')}"],
                "This machine's OpenSSL build has these legacy versions disabled at the "
                "library level, so the tool could not even offer them. The server's "
                "behaviour toward them is therefore UNKNOWN — this is a client limitation, "
                "not evidence that the server rejects them.",
                "No direct impact. Recorded so the report does not falsely claim a clean "
                "result for protocol versions that were never actually tested.",
                "Verify independently with an external service such as "
                "https://www.ssllabs.com/ssltest/ or `nmap --script ssl-enum-ciphers -p "
                f"{port} {host}` (only if authorised)."))

    # self-signed / untrusted issuer heuristics
    if issuer.get("commonName") in (subject.get("commonName"), host) and "Let's Encrypt" not in str(issuer):
        findings.append(F(
            "TLS-SELF-SIGNED", "Certificate appears self-signed", "medium", "transport",
            [f"subject={subject}", f"issuer={issuer}"],
            "Subject and issuer match, indicating a self-signed certificate.",
            "No third-party trust anchor; browsers warn all visitors.",
            "Use a publicly trusted CA (Let's Encrypt is free)."))

    return findings, facts


# ===========================================================================
# 3. HTTP security headers
# ===========================================================================
def analyse_csp(value):
    """Judge CSP quality rather than merely noting its presence."""
    if not value:
        return {"present": False}
    directives = {}
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        bits = chunk.split()
        directives[bits[0].lower()] = bits[1:]
    only_upgrade = set(directives) <= {"upgrade-insecure-requests"}
    weak_tokens = []
    for src in ("script-src", "default-src", "object-src", "base-uri"):
        vals = directives.get(src, [])
        for bad in ("'unsafe-inline'", "'unsafe-eval'", "*"):
            if bad in vals:
                weak_tokens.append(f"{src} contains {bad}")
    if "script-src" in directives and "'unsafe-inline'" in directives["script-src"]:
        weak_tokens.append("script-src 'unsafe-inline' largely defeats CSP's XSS protection")
    return {
        "present": True, "raw": value, "directives": directives,
        "only_upgrade_insecure": only_upgrade, "weak_tokens": weak_tokens,
        "has_frame_ancestors": "frame-ancestors" in directives,
        "has_script_src": "script-src" in directives,
        "has_reporting": bool(directives.get("report-uri") or directives.get("report-to")),
    }


def analyse_hsts(value):
    if not value:
        return {"present": False}
    max_age = 0
    m = re.search(r"max-age=(\d+)", value)
    if m:
        max_age = int(m.group(1))
    return {
        "present": True, "raw": value, "max_age": max_age,
        "days": round(max_age / 86400, 1),
        "include_subdomains": "includesubdomains" in value.lower(),
        "preload": "preload" in value.lower(),
        "preload_eligible": max_age >= 31536000 and "includesubdomains" in value.lower()
                            and "preload" in value.lower(),
    }


def check_headers(client, target, extra_paths=("/",)):
    findings, facts = [], {}
    per_path = {}
    for path in extra_paths:
        url = target["base"] + path
        resp = client.get(url, follow=True)
        if resp.get("status") is None:
            continue
        per_path[path] = {"status": resp["status"], "headers": resp.get("headers", {})}
    facts["per_path"] = {p: v["status"] for p, v in per_path.items()}
    if "/" not in per_path:
        return [F("HTTP-UNREACHABLE", "Target did not respond", "high", "transport",
                  [target["base"]], "No HTTP response obtained.",
                  "Cannot assess.", "Verify the target is reachable.")], facts

    primary = per_path["/"]["headers"]
    facts["server"] = webfetch.Client.header(primary, "Server")
    facts["cookies"] = webfetch.Client.all_headers(primary, "Set-Cookie")

    # ---- missing headers ----
    missing = []
    for name, sev, why in SECURITY_HEADERS:
        if webfetch.Client.header(primary, name) is None:
            missing.append((name, sev, why))
    facts["missing_headers"] = [m[0] for m in missing]

    hsts = analyse_hsts(webfetch.Client.header(primary, "Strict-Transport-Security"))
    facts["hsts"] = hsts
    csp = analyse_csp(webfetch.Client.header(primary, "Content-Security-Policy"))
    facts["csp"] = csp

    if not hsts["present"]:
        findings.append(F(
            "HDR-NO-HSTS", "Missing Strict-Transport-Security", "medium", "transport",
            ["Strict-Transport-Security: absent",
             f"Server header: {facts['server'] or 'not disclosed'}"],
            "Even with an HTTP->HTTPS redirect in place, the redirect itself travels over "
            "cleartext HTTP. Without HSTS the browser only learns to prefer HTTPS *after* "
            "making that first insecure request.",
            "An attacker able to intercept traffic (hostile Wi-Fi, compromised router, "
            "ARP spoofing) can suppress the redirect and hold the victim on HTTP — the "
            "classic SSL-strip attack. Also blocks HSTS preload list submission.",
            "Header always set Strict-Transport-Security \"max-age=31536000; "
            "includeSubDomains\" env=HTTPS  —  deploy first with max-age=300 and test "
            "EVERY subdomain over HTTPS, since includeSubDomains forces all of them. "
            "Then extend to one year and consider preload submission."))
    elif hsts["max_age"] < 15768000:
        findings.append(F(
            "HDR-HSTS-SHORT", f"HSTS max-age too short ({hsts['days']} days)", "low",
            "transport", [hsts["raw"]],
            "Short max-age windows limit protection and disqualify preload listing.",
            "Users are unprotected once the window lapses.",
            "Increase to max-age=31536000 (1 year) once all subdomains are verified."))
    if hsts["present"] and hsts["include_subdomains"]:
        findings.append(F(
            "HDR-HSTS-SUBDOMAINS", "HSTS includeSubDomains is set — verify all subdomains",
            "info", "transport", [hsts["raw"]],
            "includeSubDomains forces HTTPS on every subdomain. Any subdomain that does "
            "not serve valid HTTPS will break.",
            "Outages for subdomains that are HTTP-only or have certificate problems.",
            "Enumerate all DNS records and confirm each serves valid HTTPS before "
            "relying on this. Particularly check ftp/mail/autodiscover hosts."))

    if not csp["present"]:
        findings.append(F(
            "HDR-NO-CSP", "No Content-Security-Policy header", "low", "headers",
            ["Content-Security-Policy: absent"],
            "No policy restricts which origins may supply scripts, styles, frames or "
            "connections.",
            "Removes the strongest defence-in-depth layer against XSS and data injection. "
            "Also means no CSP telemetry, so you get no visibility into injection attempts.",
            "Start with Content-Security-Policy-Report-Only, tune against real violations "
            "for a week, then enforce. Include frame-ancestors, base-uri 'self', "
            "object-src 'none' and form-action limited to your form provider."))
    elif csp["only_upgrade_insecure"]:
        findings.append(F(
            "HDR-CSP-INEFFECTIVE",
            "CSP contains only upgrade-insecure-requests (no real policy)", "low", "headers",
            [f"Content-Security-Policy: {csp['raw']}"],
            "The sole directive rewrites http: subresource URLs to https:. It places no "
            "restriction on script, style, frame or connect sources. Automated scanners "
            "that merely test for header presence will report 'CSP present' here, which "
            "is misleading.",
            "No XSS or data-injection mitigation is actually provided by this policy.",
            "Replace with a real allowlist policy. Note 'unsafe-inline' in style-src is "
            "often required by CSS-in-JS and Tailwind runtime injection; keep script-src "
            "free of it."))
    elif csp["weak_tokens"]:
        findings.append(F(
            "HDR-CSP-WEAK", "CSP present but contains weak directives", "medium", "headers",
            csp["weak_tokens"] + [csp["raw"]],
            "A CSP that permits 'unsafe-inline' or 'unsafe-eval' for scripts can be "
            "bypassed by most real XSS payloads, reducing it to near-zero value.",
            "The policy gives a false sense of protection while not meaningfully raising "
            "the bar for an attacker.",
            "Remove 'unsafe-inline' from script-src by adopting nonces or hashes; remove "
            "'unsafe-eval' by eliminating eval-dependent code."))
    if csp["present"] and not csp["has_frame_ancestors"]:
        findings.append(F(
            "HDR-CSP-NO-FRAME-ANCESTORS", "CSP has no frame-ancestors directive", "low",
            "headers", [csp["raw"]],
            "frame-ancestors is the modern clickjacking control and is not present.",
            "Page may be framed by any origin unless X-Frame-Options covers it.",
            "Add frame-ancestors 'self' (or 'none')."))
    if csp["present"] and not csp["has_reporting"]:
        findings.append(F(
            "HDR-CSP-NO-REPORTING", "CSP has no report-uri/report-to", "info", "headers",
            [csp["raw"]],
            "No violation reporting endpoint is configured.",
            "You receive no telemetry on blocked loads or injection attempts, so a "
            "misconfiguration or an active attack goes unnoticed.",
            "Add report-to with a Reporting-API endpoint or a service like report-uri.com."))

    # ---- clickjacking ----
    xfo = webfetch.Client.header(primary, "X-Frame-Options")
    framed = (xfo is None) and not csp.get("has_frame_ancestors")
    facts["xfo"] = xfo
    facts["frameable"] = framed
    if framed:
        findings.append(F(
            "HDR-CLICKJACK", "No clickjacking protection (X-Frame-Options and frame-ancestors both absent)",
            "medium", "headers",
            ["X-Frame-Options: absent", "CSP frame-ancestors: absent"],
            "Nothing prevents the site being embedded in an iframe on an attacker-"
            "controlled page, where a transparent overlay can induce clicks on elements "
            "the victim believes belong elsewhere.",
            "Impact scales with what the page can *do*. A pure brochure page is low risk; "
            "a page with forms that submit real data — contact forms, payment, file "
            "upload, settings changes — can be driven by the attacker. Check the "
            "form-bearing routes specifically.",
            "Set both: X-Frame-Options SAMEORIGIN (legacy coverage) and CSP frame-ancestors "
            "'self' (modern). Use DENY / 'none' if the site should never be framed."))

    # ---- other hardening headers ----
    others = [(n, s, w) for n, s, w in SECURITY_HEADERS
              if n not in ("Strict-Transport-Security", "Content-Security-Policy",
                           "X-Frame-Options", "Cross-Origin-Embedder-Policy")]
    still_missing = [(n, s, w) for n, s, w in others
                     if webfetch.Client.header(primary, n) is None]
    if still_missing:
        findings.append(F(
            "HDR-BASELINE-GAPS",
            f"Missing baseline hardening headers: {', '.join(n for n, _, _ in still_missing)}",
            "low", "headers",
            [f"{n}: absent — {w}" for n, _, w in still_missing],
            "Individually low impact; collectively the absence of a hardening baseline.",
            "X-Content-Type-Options:nosniff prevents MIME-sniffing script execution. "
            "Referrer-Policy stops internal URLs and query strings leaking to third-party "
            "origins you link to. Permissions-Policy disables browser features you do not "
            "use, shrinking the blast radius of any future XSS.",
            "Header always set X-Content-Type-Options nosniff / Referrer-Policy "
            "strict-origin-when-cross-origin / Permissions-Policy \"geolocation=(), "
            "microphone=(), camera=(), payment=()\". Use 'always' so headers are also "
            "emitted on 4xx/5xx."))

    # ---- info disclosure ----
    leaks = []
    for h in DISCLOSURE_HEADERS:
        v = webfetch.Client.header(primary, h)
        if v:
            leaks.append(f"{h}: {v}")
    server = facts["server"] or ""
    if re.search(r"(apache|nginx|litespeed|iis|tomcat)[/\s][\d\.]+", server, re.I):
        leaks.append(f"Server discloses version: {server}")
    facts["disclosure"] = leaks
    if leaks:
        findings.append(F(
            "HDR-DISCLOSURE", "Technology/platform information disclosure", "low", "infra",
            leaks,
            "Response headers identify the server, hosting platform, control panel or "
            "framework. This hands an attacker an accurate stack description without any "
            "fingerprinting effort.",
            "Enables targeted exploitation of known issues in that specific stack, and "
            "helps an attacker decide whether the target is worth pursuing. Note that "
            "disclosing the *product* without a *version* limits this considerably.",
            "Header unset platform / Header unset panel / Header unset X-Powered-By. "
            "Suppressing Server entirely often requires host-level config or a support "
            "request on shared hosting. A CDN/WAF in front also masks this."))

    # ---- cookies ----
    if facts["cookies"]:
        bad = []
        for c in facts["cookies"]:
            low = c.lower()
            issues = [x for x, need in (("Secure", "secure"), ("HttpOnly", "httponly"),
                                        ("SameSite", "samesite")) if need not in low]
            if issues:
                bad.append(f"{c.split('=')[0]} missing {', '.join(issues)}")
        facts["cookie_issues"] = bad
        if bad:
            findings.append(F(
                "HDR-COOKIE-FLAGS", "Cookies missing security attributes", "medium", "headers",
                bad,
                "Cookies without Secure can be sent over cleartext HTTP; without HttpOnly "
                "they are readable by any injected script; without SameSite they are sent "
                "on cross-site requests.",
                "Session hijacking via network interception or XSS, and CSRF exposure.",
                "Set Secure; HttpOnly; SameSite=Lax (or Strict) on all session cookies."))
    else:
        facts["stateless"] = True

    # ---- inconsistent headers across paths ----
    if len(per_path) > 1:
        ref = {k.lower() for k in primary}
        for path, data in per_path.items():
            if path == "/":
                continue
            there = {k.lower() for k in data["headers"]}
            lost = sorted((ref & {n.lower() for n, _, _ in SECURITY_HEADERS}) - there)
            if lost:
                findings.append(F(
                    "HDR-INCONSISTENT", f"Security headers absent on {path} but present on /",
                    "low", "headers",
                    [f"{path} is missing: {', '.join(lost)}",
                     f"status on {path}: {data['status']}"],
                    "Header policy is applied inconsistently. Attackers preferentially "
                    "target the least-protected path, and error pages are commonly served "
                    "by different software (hosting platform defaults) that never sees "
                    "your configuration.",
                    "A control that appears to be deployed is not actually enforced across "
                    "the site. Error pages frequently lack CSP entirely.",
                    "Apply headers with the 'always' keyword so they cover error responses, "
                    "or take control of error pages with a custom ErrorDocument."))
    return findings, facts


# ===========================================================================
# 4. HTTP surface: routing, methods, standards files, source maps
# ===========================================================================
def check_surface(client, target, html_text, asset_paths):
    findings, facts = [], {}
    base = target["base"]

    # ---- allowed methods ----
    opts = client.request(base + "/", method="OPTIONS")
    allow = webfetch.Client.header(opts.get("headers"), "Allow")
    facts["allow"] = allow
    probe = {}
    for m in ("PUT", "DELETE", "PATCH", "TRACE"):
        r = client.request(base + "/", method=m)
        probe[m] = r.get("status")
    facts["method_probe"] = probe
    # 405 (Method Not Allowed) and 501 (Not Implemented) both mean the method is
    # REFUSED — that is the desired outcome. Only a 2xx means it is honoured.
    # Flagging 405 as "TRACE enabled" is a classic scanner false positive.
    if probe.get("TRACE") == 200:
        findings.append(F(
            "HTTP-TRACE", "TRACE method is enabled", "medium", "http",
            [f"TRACE -> {probe.get('TRACE')}"],
            "TRACE echoes the request back including headers, enabling cross-site tracing.",
            "Credential and cookie theft via XST when combined with another injection flaw.",
            "Disable TRACE. Apache/LiteSpeed: TraceEnable off"))
    facts["trace_refused"] = probe.get("TRACE") in (405, 501, 403, 400)
    risky = [m for m in ("PUT", "DELETE", "PATCH") if probe.get(m) in (200, 204)]
    if risky:
        findings.append(F(
            "HTTP-WRITE-METHODS", f"Write-capable HTTP methods accepted: {risky}", "high",
            "http", [f"{m} -> {probe[m]}" for m in risky],
            "The server accepts methods that can modify or delete resources.",
            "Potential for unauthorised content modification or deletion.",
            "Restrict to GET/HEAD/POST unless the application genuinely requires more, and "
            "authenticate any that do."))
    facts["methods_ok"] = not risky and probe.get("TRACE") not in (200, 405)

    # ---- standards files ----
    facts["standards_files"] = {}
    for path, purpose in STANDARDS_FILES:
        r = client.get(base + path)
        facts["standards_files"][path] = r.get("status")
    sec_txt = facts["standards_files"].get("/.well-known/security.txt")
    legacy = facts["standards_files"].get("/security.txt")
    if sec_txt not in (200,) and legacy not in (200,):
        findings.append(F(
            "HTTP-NO-SECURITYTXT", "No RFC 9116 security.txt / disclosure contact", "low",
            "process", [f"/.well-known/security.txt -> {sec_txt}",
                        f"/security.txt -> {legacy}"],
            "There is no defined, low-friction channel for a researcher to report a "
            "vulnerability.",
            "Issues go unreported, or get published without warning because the reporter "
            "had nowhere to send them.",
            f"Serve /.well-known/security.txt with Contact:, Expires:, "
            f"Preferred-Languages: and Canonical: fields. Add a plain-language disclosure "
            f"policy page and link it from the footer."))
    if facts["standards_files"].get("/robots.txt") != 200:
        findings.append(F(
            "HTTP-NO-ROBOTS", "No robots.txt", "info", "process",
            ["/robots.txt -> " + str(facts["standards_files"].get("/robots.txt"))],
            "Crawlers receive no directives. Not a security control — robots.txt is not "
            "access control and sensitive paths must never rely on it.",
            "Minor SEO and crawl-budget impact.",
            "Add robots.txt and, for a SPA, a sitemap.xml listing real routes."))

    # ---- SPA route fallback ----
    routes = extract_routes(html_text) if html_text else []
    facts["routes"] = routes
    if routes:
        testable = [r for r in routes if r not in ("/",) and ":" not in r][:5]
        results = {}
        for r in testable:
            res = client.get(base + r, follow=False)
            results[r] = res.get("status")
        facts["route_status"] = results
        broken = [r for r, s in results.items() if s == 404]
        if broken and results.get(testable[0]) == 404:
            findings.append(F(
                "HTTP-SPA-NO-FALLBACK",
                f"SPA deep links return 404 — no fallback rewrite ({len(broken)}/{len(results)} tested)",
                "low", "app",
                [f"{r} -> {s}" for r, s in results.items()] +
                [f"routes declared in bundle: {len(routes)}"],
                "The server has no rewrite sending unknown paths to the SPA shell. "
                "Client-side navigation works because the router intercepts clicks, but "
                "any direct request, bookmark, refresh, shared link or crawler hit on an "
                "internal route fails.",
                "Primarily a functional and SEO defect, but security-relevant: it routes "
                "a large share of real traffic onto the hosting platform's default error "
                "page, which you do not control. That page typically carries no CSP, may "
                "inject the host's own analytics tags under your domain, and may load "
                "end-of-life third-party libraries. It also makes header policy "
                "inconsistent. Any route reached by direct link — including parameterised "
                "ones like /apply/:id that candidates may receive by email — is broken.",
                "Add a fallback rewrite: RewriteCond %{REQUEST_FILENAME} !-f, !-d then "
                "RewriteRule ^ index.html [L]. Or serve a custom ErrorDocument 404 that "
                "boots the router. Better still, pre-render routes to real HTML files."))

    # ---- source maps ----
    facts["source_maps"] = {}
    for path in asset_paths:
        if path.endswith(".js"):
            for cand in (path + ".map", path.replace(".js", ".js.map")):
                r = client.get(base + cand)
                facts["source_maps"][cand] = r.get("status")
                if r.get("status") == 200:
                    findings.append(F(
                        "HTTP-SOURCEMAP", f"Source map published at {cand}", "high", "app",
                        [f"GET {base}{cand} -> 200"],
                        "Source maps allow the original, unminified source to be "
                        "reconstructed — including comments, internal variable names, "
                        "unreferenced code paths and sometimes removed credentials.",
                        "Dramatically lowers the effort of finding further weaknesses, and "
                        "can directly expose secrets that were stripped from the build but "
                        "retained in the map.",
                        "Disable sourcemap generation for production builds "
                        "(build.sourcemap: false in Vite) or upload maps to your error "
                        "tracker instead of serving them publicly."))
                break

    # ---- inline sourceMappingURL comments ----
    return findings, facts


def extract_routes(text):
    """Pull react-router/vue-router style paths out of a bundle."""
    if not text:
        return []
    found = re.findall(r'path\s*:\s*"(/[^"]{0,60})"', text)
    found += re.findall(r'path\s*:\s*\'(/[^\']{0,60})\'', text)
    seen, out = set(), []
    for f in found:
        if f not in seen and not f.startswith("//"):
            seen.add(f)
            out.append(f)
    return out


# ===========================================================================
# 5. Client-side bundle analysis
# ===========================================================================
def scan_secrets(blobs, context=140):
    """
    blobs: {path: text}. Returns hits with FILE ATTRIBUTION.

    Attribution matters: a reviewer must be able to see whether a match came from
    application code or a vendored library chunk before deciding severity.
    """
    hits = []
    for path, text in blobs.items():
        vendor = is_vendor_chunk(path)
        for label, pattern in SECRET_PATTERNS.items():
            for m in re.finditer(pattern, text):
                start = max(0, m.start() - context)
                segment = text[start:m.end() + context]
                if _noise(segment):
                    continue
                hits.append({
                    "label": label, "match": m.group(0)[:160],
                    "context": segment.replace("\n", " ")[:340],
                    "offset": m.start(), "file": path, "vendor_chunk": vendor,
                    "public_by_design": label in PUBLIC_BY_DESIGN,
                })
    return hits


def scan_sinks(blobs, patterns, context=160):
    """
    Two-stage filtering, because one stage is not enough:

      Stage 1 - FILENAME. If every match for a sink lives in vendor chunks
                (framework-*.js, main-*.js, react-dom*.js, polyfills-*.js) then
                it is library internals. This is the reliable signal and works
                across bundlers.
      Stage 2 - SIGNATURE. For single-bundle builds (Vite emits one index-*.js
                containing vendor AND app code), filenames cannot separate them,
                so fall back to LIBRARY_NOISE signatures.

    The result records which stage did the work, so a reviewer can judge how much
    to trust the negative. Under-reporting a real sink is worse than the reverse,
    so anything ambiguous is surfaced rather than silently dropped.
    """
    results = {}
    for name, pattern in patterns.items():
        raw = 0
        app_hits = []
        vendor_only = 0
        single_bundle = len(blobs) == 1
        for path, text in blobs.items():
            for m in re.finditer(pattern, text):
                raw += 1
                start = max(0, m.start() - context)
                segment = text[start:m.end() + context].replace("\n", " ")
                if _noise(segment):
                    vendor_only += 1
                    continue
                if is_vendor_chunk(path):
                    vendor_only += 1
                    continue
                app_hits.append({"file": path, "context": segment[:300]})
        results[name] = {
            "raw": raw,
            "filtered_out": vendor_only,
            "in_app_code": len(app_hits),
            "samples": app_hits[:3],
            "method": ("filename+signature" if not single_bundle
                       else "signature-only (single bundle: vendor and app code are "
                            "concatenated, so filename classification is unavailable)"),
        }
    return results


INTERNAL_URL_RE = re.compile(
    r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?')


def scan_internal_urls(blobs, context=200):
    """
    Find localhost / RFC1918 URLs that leaked into application code.

    Vendor chunks are skipped entirely, and remaining matches are noise-filtered,
    because routing libraries legitimately use `http://localhost` as a fallback
    base URL when `window.location.origin` is unavailable. Reporting that as a
    leaked internal endpoint is a false positive.
    """
    out = []
    for path, text in blobs.items():
        if is_vendor_chunk(path):
            continue
        for m in INTERNAL_URL_RE.finditer(text):
            start = max(0, m.start() - context)
            seg = text[start:m.end() + context].replace("\n", " ")
            if _noise(seg):
                continue
            out.append({"file": path, "match": m.group(0), "context": seg[:300],
                        "offset": m.start()})
    return out


SINK_PATTERNS = {
    "dangerouslySetInnerHTML": r'dangerouslySetInnerHTML',
    "innerHTML": r'\.innerHTML\s*=',
    "outerHTML": r'\.outerHTML\s*=',
    "insertAdjacentHTML": r'insertAdjacentHTML\s*\(',
    "document.write": r'document\.write\s*\(',
    "eval": r'[^.\w]eval\s*\(',
    "new Function": r'new\s+Function\s*\(',
    "javascript: URI": r'["\']javascript:',
    "setTimeout(string)": r'setTimeout\s*\(\s*["\']',
    "location from URL param": r'(?:location\.(?:href|assign|replace))\s*\(\s*[^)]*(?:searchParams|URLSearchParams|location\.(?:search|hash))',
}


def check_bundle(client, target, html_text):
    findings, facts = [], {}
    base = target["base"]
    if not html_text:
        return findings, facts

    # ---- asset discovery (HTML-referenced first, then bundled imports) ----
    assets = re.findall(r'(?:src|href)="(/[^"]+\.(?:js|css|mjs))"', html_text)
    assets += re.findall(r'"(/(?:_next|assets|static)/[^"]+\.(?:js|css|mjs))"', html_text)
    assets = list(dict.fromkeys(assets))
    facts["assets"] = assets
    if not assets:
        facts["note"] = "no local JS/CSS assets referenced from HTML"
        return findings, facts

    blobs = {}
    for path in assets[:14]:  # bounded to respect the request budget
        r = client.get(base + path)
        if r.get("status") == 200 and r.get("body"):
            blobs[path] = r["body"].decode("utf-8", "replace")
    facts["fetched_assets"] = {p: len(t) for p, t in blobs.items()}
    facts["chunk_classification"] = {
        "vendor": [p for p in blobs if is_vendor_chunk(p)],
        "application": [p for p in blobs if not is_vendor_chunk(p)],
    }
    if not blobs:
        return findings, facts

    app_text = "\n".join(t for p, t in blobs.items() if not is_vendor_chunk(p))
    combined = "\n".join(blobs.values())
    # Where vendor/app could not be separated, say so explicitly rather than
    # silently analysing the concatenation.
    facts["separable"] = bool(app_text) and len(blobs) > 1

    # ---- secrets ----
    hits = scan_secrets(blobs)
    facts["secret_hits"] = hits
    real = [h for h in hits if not h["public_by_design"]]
    public = [h for h in hits if h["public_by_design"]]

    if real:
        findings.append(F(
            "JS-SECRETS", f"Hardcoded credentials/secrets in client bundle ({len(real)})",
            "critical", "app",
            [f"[{h['label']}] {h['match']}  ({h['file']}, offset {h['offset']})"
             for h in real[:15]],
            "Anything shipped to the browser is public by construction. These matches "
            "survived framework-internals filtering. Before escalating, confirm each one "
            "manually: the highest-value patterns (AWS, Stripe secret, private key blocks) "
            "are almost never false positives, but generic assignments can be.",
            "Whoever holds these values can impersonate the service, read or modify data, "
            "incur cost, or pivot to other systems. Treat any confirmed secret as already "
            "compromised — it has been public since the build was deployed.",
            "Rotate every confirmed credential immediately; rotation, not removal, is the "
            "fix. Move secret use behind a server-side proxy so keys never reach the "
            "client. Add a pre-commit scanner (gitleaks, trufflehog) and CI gating so it "
            "cannot recur."))

    if public:
        findings.append(F(
            "JS-FORM-ENDPOINTS",
            f"Client-side service endpoints exposed ({len(public)})", "medium", "app",
            [f"[{h['label']}] {h['match']}  ({h['file']})" for h in public[:8]],
            "These keys are designed to be embedded client-side (Web3Forms, Formspree, "
            "Formcarry and Algolia search-only keys all work this way), so this is NOT a "
            "credential leak and must not be reported as one. The real risk is that the "
            "endpoints are reachable directly, bypassing your website entirely, and most "
            "providers do not restrict origin by default.",
            "For form providers: inbox flooding and denial of service to the business; "
            "fake submissions polluting a recruitment or CRM pipeline; the form reused as "
            "a phishing relay that borrows your brand's credibility; malicious file "
            "delivery to staff; quota and cost exhaustion. For Algolia search-only keys: "
            "impact is limited to reading the search index and consuming quota, which is "
            "the intended behaviour — informational only.",
            "Form providers: enable the provider's CAPTCHA/Turnstile/hCaptcha, configure "
            "domain restriction so only your origin is accepted, add a honeypot field "
            "(Web3Forms natively rejects a truthy 'botcheck'), and enforce file type and "
            "size limits provider-side rather than only in JS. Rotate the key if you "
            "suspect harvesting. Longer term, proxy forms through a serverless function "
            "that validates input and keeps provider keys out of the public bundle. "
            "Algolia: confirm the key is search-only with restricted indices."))

    # ---- version fingerprints (heuristic — always treat as approximate) ----
    facts["versions"] = {}
    facts["version_confidence"] = {}
    rr = re.search(r'__reactRouterVersion\s*=\s*"([\d\.]+)"', combined)
    if rr:
        facts["versions"]["react-router"] = rr.group(1)
        facts["version_confidence"]["react-router"] = "high (explicit runtime version constant)"
    # React's own version marker, then looser fallbacks. Key may or may not be
    # quoted depending on the minifier, so allow both.
    for pat, conf in [(r'react-dom\.production\.min\.js\?v=([\d\.]+)', "high"),
                      (r'version["\']?\s*[:=]\s*["\'](1[5-9]\.\d+\.\d+)["\']',
                       "medium (first match wins; may belong to another library)"),
                      (r'react[@"]([\d]{1,2}\.\d+\.\d+)', "low")]:
        m = re.search(pat, combined)
        if m and "react" not in facts["versions"]:
            facts["versions"]["react"] = m.group(1)
            facts["version_confidence"]["react"] = conf
    for lib, pat in [("vue", r'Version\s*=\s*"([\d\.]+)"'),
                     ("jquery", r'jQuery v([\d\.]+)'),
                     ("bootstrap", r'Bootstrap v([\d\.]+)'),
                     ("lodash", r'lodash@([\d\.]+)'),
                     ("axios", r'axios/([\d\.]+)'),
                     ("next", r'"next"\s*:\s*"([\d\.]+)"')]:
        m = re.search(pat, combined)
        if m:
            facts["versions"][lib] = m.group(1)
            facts["version_confidence"][lib] = "medium"
    if facts["versions"] and not all(
            c.startswith("high") for c in facts["version_confidence"].values()):
        findings.append(F(
            "JS-VERSION-UNCERTAIN",
            "Component versions fingerprinted heuristically — verify before acting",
            "info", "deps",
            [f"{k} {v}  (confidence: {facts['version_confidence'].get(k,'?')})"
             for k, v in facts["versions"].items()],
            "Versions were inferred from strings in a minified bundle. Minifiers rename and "
            "inline, so a generic `version:\"x.y.z\"` match may belong to an unrelated "
            "library. Only explicit runtime constants (such as "
            "`window.__reactRouterVersion`) are reliable.",
            "Acting on a wrong version produces CVE findings that do not apply, which "
            "wastes remediation effort and undermines confidence in the rest of the report.",
            "Confirm against the authoritative source: the project's package.json and "
            "lockfile, or `npm ls <pkg>`. Do not rely on bundle fingerprinting alone."))

    # ---- RSC / server-runtime markers (drives CVE exploitability) ----
    facts["rsc_markers"] = [m for m in RSC_MARKERS if m in combined]
    facts["server_runtime_markers"] = [m for m in SERVER_RUNTIME_MARKERS if m in combined]
    facts["spa_only"] = not facts["rsc_markers"] and not facts["server_runtime_markers"]
    facts["framework_hint"] = ("next.js" if "/_next/" in combined or "_next/static" in str(assets)
                               else "vite/spa" if "/assets/index-" in str(assets)
                               else "unknown")

    # ---- dangerous sinks (two-stage filtered) ----
    facts["sinks"] = scan_sinks(blobs, SINK_PATTERNS)
    live = {k: v for k, v in facts["sinks"].items() if v["in_app_code"]}
    if live:
        findings.append(F(
            "JS-DANGEROUS-SINKS",
            "HTML/script sinks present in application code: " + ", ".join(live),
            "medium", "app",
            [f"{k}: {v['in_app_code']} in app code ({v['filtered_out']} of {v['raw']} raw "
             f"matches filtered as vendor/framework) via {v['method']}"
             for k, v in live.items()] +
            [f"{s['file']}: ...{s['context'][:180]}..."
             for v in live.values() for s in v["samples"][:2]],
            "These matches survived BOTH filtering stages, so they appear in application "
            "code rather than framework internals. Whether they are exploitable depends "
            "entirely on whether attacker-influenced data reaches them — that requires "
            "manual taint tracing which a passive scan cannot perform. Presence of a sink "
            "is not itself a vulnerability.",
            "Potential DOM-based XSS. If tainted data (URL fragment, query parameter, "
            "postMessage, stored content, third-party API response) reaches these sinks "
            "without sanitisation, an attacker can execute script in your origin.",
            "Trace each sink's data source manually. Prefer textContent over innerHTML. "
            "Where HTML rendering is genuinely required, sanitise with DOMPurify and "
            "configure a strict CSP with nonces as a backstop. Never interpolate "
            "location.hash, location.search or postMessage payloads into these APIs."))
    elif facts["sinks"] and not facts["separable"]:
        findings.append(F(
            "JS-SINKS-INCONCLUSIVE",
            "Sink analysis inconclusive — vendor and app code share one bundle",
            "info", "app",
            [f"single-bundle build; {len(blobs)} file(s) fetched",
             "raw matches: " + ", ".join(f"{k}={v['raw']}" for k, v in facts["sinks"].items()
                                        if v["raw"])],
            "This build concatenates vendor and application code into one file, so "
            "filename-based classification is unavailable and only signature filtering "
            "could be applied. Signature lists are minifier-specific and cannot be relied "
            "on to be exhaustive.",
            "A genuine application-level sink could be masked as framework internals, or "
            "vice versa. The result should be treated as unverified rather than clean.",
            "Inspect the unminified source directly (the repository, or a local build with "
            "sourcemaps) rather than relying on bundle analysis. If you control the build, "
            "enable code splitting so vendor chunks are separable."))

    # ---- sanitisation vs rendering libraries ----
    facts["sanitizers"] = [s for s in ("DOMPurify", "dompurify", "sanitize-html", "xss",
                                       "isomorphic-dompurify") if s in combined]
    facts["html_renderers"] = [s for s in ("marked", "markdown-it", "remark", "rehype",
                                          "showdown", "turndown", "highlight.js", "prismjs")
                              if s.lower() in combined.lower()]
    if facts["html_renderers"] and not facts["sanitizers"]:
        findings.append(F(
            "JS-UNSANITISED-RENDERER",
            f"HTML renderer bundled with no sanitiser ({', '.join(facts['html_renderers'])})",
            "high", "app",
            [f"renderer present: {facts['html_renderers']}",
             "DOMPurify / sanitize-html: absent"],
            "A Markdown or HTML rendering library is present but no sanitisation library "
            "was found anywhere in the bundle.",
            "If rendered content can be influenced by an attacker — user-generated content, "
            "a CMS, an API response, URL parameters — this is a direct stored or reflected "
            "XSS path.",
            "Pipe all rendered HTML through DOMPurify before insertion. If content is "
            "entirely author-controlled and static, document that assumption and add a "
            "strict CSP as a backstop."))

    # ---- external origins, PII, SRI ----
    facts["external_origins"] = sorted({
        m for m in re.findall(r'https://([a-z0-9.\-]+)', combined)
        if not any(x in m for x in ("w3.org", "react.dev", "reactrouter.com",
                                    "schema.org", "json.schemastore.org", "reactjs.org"))})
    emails = sorted(set(re.findall(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}',
                                  combined)))
    facts["emails"] = [e for e in emails
                       if not e.endswith((".png", ".jpg", ".svg", ".webp", ".js", ".css"))]
    facts["sri"] = "integrity=" in html_text
    third_party = [o for o in facts["external_origins"] if target["host"] not in o]
    if third_party and not facts["sri"]:
        findings.append(F(
            "JS-NO-SRI", "Third-party resources loaded without Subresource Integrity",
            "low", "app",
            ["integrity= attributes in HTML: 0",
             f"third-party origins referenced: {third_party[:10]}"],
            "Resources fetched from third-party origins carry no integrity hash.",
            "A compromised or DNS-hijacked CDN could serve modified script or CSS that "
            "executes with the full privileges of your origin. Google Fonts and tag "
            "managers are high-value supply-chain targets and have been abused in real "
            "attacks.",
            "Prefer self-hosting static assets — self-hosting fonts removes the request, "
            "the SRI problem, and a GDPR concern (Google Fonts leak visitor IPs to "
            "Google). Where third-party scripts are unavoidable, add integrity= and "
            "crossorigin=anonymous."))

    # ---- debug leftovers, app chunks only ----
    logs = []
    for path, text in blobs.items():
        if is_vendor_chunk(path):
            continue
        for m in re.finditer(r'console\.(log|debug|info)\s*\(', text):
            start = max(0, m.start() - 160)
            seg = text[start:m.end() + 200]
            if _noise(seg):
                continue
            logs.append({"file": path, "context": seg.replace("\n", " ")[:240]})
    facts["console_logs"] = len(logs)
    if logs:
        findings.append(F(
            "JS-CONSOLE-LOG", f"Debug logging left in production bundle ({len(logs)})",
            "info", "app",
            [f"{l['file']}: ...{l['context'][:180]}..." for l in logs[:5]],
            "console.log/debug/info calls remain in shipped APPLICATION code. Calls inside "
            "vendor chunks (framework HMR clients, React internals) were excluded, so these "
            "are yours.",
            "Can disclose API error detail, internal state, quota information or validation "
            "messages to anyone with DevTools open — including an attacker probing your "
            "endpoints.",
            "Strip in the bundler: Vite -> esbuild: { drop: ['console','debugger'] }, or "
            "terser compress.drop_console. Route real errors to an error-tracking service "
            "instead of the console."))

    # ---- dev build / env leakage ----
    if "react-dom.development" in combined or "process.env.NODE_ENV" in combined:
        findings.append(F(
            "JS-DEV-BUILD", "Development build or env references in production bundle",
            "medium", "app",
            ["react-dom.development / process.env.NODE_ENV detected"],
            "A development build appears to be served in production.",
            "Dev builds are slower, emit verbose warnings that disclose internal structure, "
            "and often bypass production safety checks.",
            "Rebuild in production mode (NODE_ENV=production) and redeploy."))
    facts["env_vars"] = sorted(set(re.findall(
        r'(?:VITE_|NEXT_PUBLIC_|REACT_APP_|VUE_APP_|NG_APP_)[A-Z_]{3,}', combined)))
    for m in re.finditer(
            r'(?:VITE_|NEXT_PUBLIC_|REACT_APP_|VUE_APP_)[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*',
            combined):
        findings.append(F(
            "JS-ENV-SECRET", f"Sensitive-looking env var inlined: {m.group(0)}", "high",
            "app", [m.group(0)],
            "Build tools inline public-prefixed environment variables directly into the "
            "bundle. A variable whose NAME implies secrecy has been marked public.",
            "The value is readable by every visitor.",
            "Never prefix a secret with VITE_/NEXT_PUBLIC_/REACT_APP_. Move it server-side "
            "and access it through an API."))

    # ---- internal/dev URLs, app chunks only ----
    internal = scan_internal_urls(blobs)
    facts["internal_urls"] = internal
    for hit in internal:
        findings.append(F(
            "JS-INTERNAL-URL",
            f"Internal/dev URL in application bundle: {hit['match']}", "low", "app",
            [f"{hit['file']}: ...{hit['context'][:260]}..."],
            "A localhost or RFC1918 address appears in shipped application code. "
            "Usually a hardcoded API base URL left over from development. Matches "
            "inside vendor chunks were excluded — router libraries legitimately "
            "reference http://localhost as a default base.",
            "Discloses internal network layout or service names, and may cause requests "
            "to fail or leak data to an unintended host.",
            "Use relative URLs or build-time environment configuration; verify no "
            "development endpoints are compiled into production."))

    return findings, facts

def check_error_page(client, target):
    """Fetch a guaranteed-nonexistent path and inspect what the platform serves."""
    findings, facts = [], {}
    import random
    import string
    slug = "nonexistent-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    r = client.get(target["base"] + "/" + slug)
    facts["path"] = "/" + slug
    facts["status"] = r.get("status")
    if r.get("status") != 404 or not r.get("body"):
        return findings, facts
    body = r["body"].decode("utf-8", "replace")
    facts["size"] = len(body)
    facts["headers"] = r.get("headers", {})

    origins = sorted(set(re.findall(r'https?://([a-z0-9.\-]+)', body)))
    facts["origins"] = origins
    scripts = re.findall(r'<script[^>]+src="([^"]+)"', body)
    facts["scripts"] = scripts
    styles = re.findall(r'<link[^>]+href="([^"]+\.css[^"]*)"', body)
    facts["styles"] = styles

    TRACKER_HOSTS = ("googletagmanager", "google-analytics", "doubleclick",
                     "facebook.net", "hotjar", "clarity.ms", "mixpanel",
                     "segment.io", "amplitude", "matomo", "piwik")
    body_lower = body.lower()
    trackers = sorted({t for t in TRACKER_HOSTS if t in body_lower})
    facts["trackers"] = trackers
    ga_ids = sorted(set(re.findall(r'\b(G-[A-Z0-9]{6,12}|UA-\d{4,}-\d+|GTM-[A-Z0-9]+)\b', body)))
    facts["ga_ids"] = ga_ids
    facts["csp_on_error_page"] = webfetch.Client.header(r.get("headers"), "Content-Security-Policy")

    if trackers:
        findings.append(F(
            "ERR-TRACKERS",
            f"Analytics/tracking tags fire on the platform error page ({len(ga_ids)} ID(s): {ga_ids or 'n/a'})",
            "medium", "privacy",
            [f"GET {facts['path']} -> 404", f"scripts: {scripts[:5]}",
             f"third-party origins: {origins[:8]}",
             f"CSP on this page: {facts['csp_on_error_page'] or 'ABSENT'}"],
            "The hosting platform's default error page injects its own analytics and "
            "advertising tags, served under YOUR domain. Verify whether these IDs belong "
            "to you or to the host — compare against your own site's tags. If they do not "
            "appear in your application bundle, they are the platform's.",
            "Visitors who hit any broken URL are tracked by a third party you do not "
            "control, with no consent mechanism and no privacy-notice disclosure. Under "
            "GDPR/ePrivacy and similar regimes this is the site operator's responsibility "
            "regardless of who injected the code — and the operator is often unaware it "
            "happens. Requests to advertising domains (e.g. doubleclick.net) compound "
            "this. No CSP is applied to the page, so nothing constrains what it executes.",
            "Take control of error pages: ErrorDocument 404 /index.html (or a purpose-"
            "built /404.html you own). For a SPA this simultaneously fixes deep-link "
            "routing. If that is not possible, ask your host to remove the tags. Deploy a "
            "consent-management mechanism for any analytics you do run, and update the "
            "privacy policy to list every third party processing visitor data."))

    eol = []
    for s in styles + scripts:
        if re.search(r'bootstrap[/\-]?[123]\.', s) or "bootstrap/3." in s:
            eol.append(f"Bootstrap 3.x (EOL, XSS advisories CVE-2019-8331, "
                       f"CVE-2018-14040/41/42): {s}")
        if "maxcdn.bootstrapcdn.com" in s:
            eol.append(f"Deprecated BootstrapCDN host (service migrated to "
                       f"cdn.jsdelivr.net): {s}")
        if re.search(r'jquery[.\-](1\.[0-9]|2\.[0-9]|3\.[0-4])\.', s):
            eol.append(f"Outdated jQuery: {s}")
    facts["eol_libs"] = eol
    if eol:
        # The Bootstrap 3.x XSS advisories all require Bootstrap's JS plugins.
        # Determine whether any JS is actually loaded, so we do not over-report
        # a CSS-only stylesheet as an exploitable XSS.
        has_bootstrap_js = any(re.search(r'bootstrap[^"\']*\.js', s, re.I) for s in scripts)
        has_jquery = any("jquery" in s.lower() for s in scripts)
        expl = has_bootstrap_js and has_jquery
        facts["bootstrap_js"] = has_bootstrap_js
        facts["jquery"] = has_jquery
        findings.append(F(
            "ERR-EOL-LIBS",
            f"End-of-life libraries on the platform error page ({len(eol)})",
            "low" if not expl else "medium", "app",
            eol + [f"bootstrap JS present: {has_bootstrap_js}",
                   f"jquery present: {has_jquery}",
                   f"CSS-only (no script execution path): {not expl}"],
            "The Bootstrap 3.x XSS advisories (CVE-2019-8331 tooltip/popover data-template, "
            "CVE-2018-14040 collapse data-parent, CVE-2018-14041 data-container, "
            "CVE-2018-14042 data-target) all require Bootstrap's JAVASCRIPT plugins. If "
            "only the stylesheet is loaded and jQuery is absent, there is no script "
            "execution path and they are NOT exploitable — record the distinction rather "
            "than over-reporting." if not expl else
            "Bootstrap JavaScript is present, so the known XSS advisories may apply.",
            "Primarily scan noise: any automated scanner will flag this and bury real "
            "findings. The deprecated CDN host is a genuine availability and supply-chain "
            "risk on a page served under your domain." +
            ("" if not expl else " Potential XSS if untrusted data reaches the plugins."),
            "Resolved by replacing the platform error page with your own (see ERR-TRACKERS). "
            "This is host-controlled code and cannot be patched from the customer side."))

    return findings, facts
