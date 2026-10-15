"""
dnslib.py — minimal DNS resolver using only the Python standard library.

Why hand-roll this instead of shelling out to `dig`?
  * `dig` / `nslookup` / `host` are frequently absent (slim containers, macOS
    without bind-utils, CI runners). sockets + struct are always available.
  * You control the exact bytes on the wire, so you can set the DO bit for
    DNSSEC checks and inspect rcode rather than parsing human-facing text.

Only recursive *lookups* are performed, against a public resolver. This is the
same thing your OS does when you visit the site — it is not a zone transfer and
not a brute-force enumeration.
"""

import random
import socket
import struct

DEFAULT_SERVERS = ["1.1.1.1", "9.9.9.9", "8.8.8.8"]

QT = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "DNSKEY": 48, "RRSIG": 46, "DS": 43, "CAA": 257,
    "HTTPS": 65,
}
RTYPE_NAME = {v: k for k, v in QT.items()}


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _parse_name(data: bytes, offset: int):
    """Follow compression pointers. Returns (name, next_offset)."""
    labels, jumped, original = [], False, offset
    seen = 0
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                original = offset + 2
            offset = pointer
            jumped = True
            seen += 1
            if seen > 16:  # pointer loop guard
                break
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
    if not labels:
        # The DNS root label. Matters for null MX records ("0 .", RFC 7505),
        # which declare that a domain accepts no mail at all. Returning ""
        # instead of "." made that indistinguishable from a parse failure.
        return ".", (original if jumped else offset)
    return ".".join(labels), (original if jumped else offset)


def _build_query(name: str, qtype: int, tid: int, dnssec: bool = False) -> bytes:
    flags = 0x0100 | (0x0010 if dnssec else 0x0000)  # RD, optionally DO
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack(">HH", qtype, 1)


def query(name, qtype, server=None, timeout=6.0, dnssec=False, retries=2):
    """Resolve one record type. Returns dict with rcode, answers, raw rcode text."""
    servers = [server] if server else DEFAULT_SERVERS
    last_err = None
    for srv in servers:
        for _ in range(retries):
            tid = random.randint(0, 0xFFFF)
            packet = _build_query(name, QT[qtype], tid, dnssec)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(packet, (srv, 53))
                data, _ = sock.recvfrom(65535)
            except Exception as exc:  # noqa: BLE001 - resolver may fail for many reasons
                last_err = f"{type(exc).__name__}: {exc}"
                continue
            finally:
                sock.close()
            return _parse_response(data, tid)
    return {"rcode": None, "answers": [], "error": last_err or "no resolver responded"}


def _parse_response(data: bytes, expected_tid: int) -> dict:
    if len(data) < 12:
        return {"rcode": None, "answers": [], "error": "truncated response"}
    tid, _flags, _qd, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    rcode = data[3] & 0x0F
    truncated = bool(data[2] & 0x02)
    offset = 12
    # skip the question section
    _, offset = _parse_name(data, offset)
    offset += 4

    def _read_records(count, section):
        recs = []
        nonlocal offset
        for _ in range(count):
            _, offset = _parse_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlen]
            offset += rdlen
            recs.append({
                "section": section,
                "type": RTYPE_NAME.get(rtype, f"TYPE{rtype}"),
                "ttl": ttl,
                "value": _decode_rdata(rtype, rdata, data, offset - rdlen),
            })
        return recs

    # Parse each section separately. This matters: a negative answer (NXDOMAIN or
    # NOERROR-with-no-data) carries an SOA in the AUTHORITY section. If authority
    # records were mixed into `answers`, callers would see a bogus "resolved"
    # value for a name that does not actually exist.
    answers = _read_records(ancount, "answer")
    authority = _read_records(nscount, "authority")
    additional = _read_records(arcount, "additional")

    return {
        "rcode": rcode,
        "rcode_text": {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                       4: "NOTIMP", 5: "REFUSED"}.get(rcode, str(rcode)),
        "truncated": truncated,
        "answers": answers,
        "authority": authority,
        "additional": additional,
        "all_answers": answers + authority + additional,
    }


def _decode_rdata(rtype: int, rdata: bytes, full: bytes, rdata_offset: int):
    try:
        if rtype == 1 and len(rdata) == 4:
            return ".".join(str(b) for b in rdata)
        if rtype == 28 and len(rdata) == 16:
            return ":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2))
        if rtype in (2, 5, 12):
            return _parse_name(full, rdata_offset)[0]
        if rtype == 6:  # SOA
            mname, off = _parse_name(full, rdata_offset)
            rname, off = _parse_name(full, off)
            nums = struct.unpack(">IIIII", full[off:off + 20]) if off + 20 <= len(full) else ()
            return f"{mname} {rname}" + (f" serial={nums[0]}" if nums else "")
        if rtype == 15:
            preference = struct.unpack(">H", rdata[:2])[0]
            return f"{preference} {_parse_name(full, rdata_offset + 2)[0]}"
        if rtype == 16:
            chunks, i = [], 0
            while i < len(rdata):
                length = rdata[i]
                chunks.append(rdata[i + 1:i + 1 + length].decode("utf-8", "replace"))
                i += 1 + length
            return "".join(chunks)
        if rtype == 257 and len(rdata) > 2:
            flags, taglen = rdata[0], rdata[1]
            tag = rdata[2:2 + taglen].decode("utf-8", "replace")
            value = rdata[2 + taglen:].decode("utf-8", "replace")
            return f'{flags} {tag} "{value}"'
        if rtype == 43:
            return rdata.hex()
        if rtype in (46, 48):
            return f"<{RTYPE_NAME.get(rtype)} present, {len(rdata)} bytes>"
    except Exception:  # noqa: BLE001 - malformed record, fall through to hex
        pass
    return rdata.hex()


def values(name, qtype, **kwargs):
    """Convenience: return just the rdata strings, or [] on any failure."""
    res = query(name, qtype, **kwargs)
    return [a["value"] for a in res.get("answers", [])]


# ---------------------------------------------------------------------------
# Domain-specific helpers used by the checks
# ---------------------------------------------------------------------------

COMMON_DKIM_SELECTORS = [
    "default", "google", "google1", "google2", "google3",
    "hostinger", "hostingermail", "hostinger1", "hmail",
    "mail", "smtp", "mx", "email", "s1", "s2", "s3", "k1", "k2", "k3",
    "selector1", "selector2", "selector-a", "selector-b",
    "dkim", "dkim1", "dkim2", "dkim-mail", "zoho", "protonmail", "sig", "sig1",
    "api", "ph", "ph1", "reseller", "web", "send", "bounce", "mailo", "zmail",
    "20230601", "20240101", "20250101", "20260101",
]

COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "pop", "pop3", "imap", "webmail", "cpanel", "ftp",
    "sftp", "admin", "portal", "api", "dev", "development", "staging", "stage",
    "test", "testing", "beta", "uat", "qa", "app", "apps", "dashboard", "panel",
    "blog", "shop", "store", "cdn", "static", "assets", "media", "vpn", "remote",
    "autodiscover", "autoconfig", "m", "mobile", "new", "old", "backup",
    "db", "database", "mysql", "sql", "phpmyadmin", "jenkins", "git", "gitlab",
    "jira", "confluence", "grafana", "kibana", "prometheus", "status",
]


def parse_spf(txt_records):
    """Pull the SPF record out of a TXT answer set and classify the qualifier."""
    spf = next((t for t in txt_records if t.lower().startswith("v=spf1")), None)
    if not spf:
        return {"present": False}
    if spf.rstrip().endswith("-all"):
        qualifier, strength = "-all", "hardfail (strict)"
    elif spf.rstrip().endswith("~all"):
        qualifier, strength = "~all", "softfail (advisory only)"
    elif spf.rstrip().endswith("?all"):
        qualifier, strength = "?all", "neutral (no protection)"
    elif spf.rstrip().endswith("+all"):
        qualifier, strength = "+all", "DANGEROUS - permits any sender"
    else:
        qualifier, strength = "absent", "no all mechanism - treated as neutral"
    return {
        "present": True, "record": spf, "qualifier": qualifier,
        "strength": strength, "includes": spf.count("include:"),
        "ptr_used": " ptr" in spf.lower(),
    }


def parse_dmarc(txt_records):
    """Parse a DMARC record and judge whether it actually enforces."""
    rec = next((t for t in txt_records if t.lower().startswith("v=dmarc1")), None)
    if not rec:
        return {"present": False}
    parts = {}
    for chunk in rec.split(";"):
        chunk = chunk.strip()
        if "=" in chunk:
            key, val = chunk.split("=", 1)
            parts[key.strip().lower()] = val.strip()
    policy = parts.get("p", "none").lower()
    return {
        "present": True,
        "record": rec,
        "policy": policy,
        "enforcing": policy in ("quarantine", "reject"),
        "subdomain_policy": parts.get("sp", "(inherits p)"),
        "reporting": parts.get("rua") or parts.get("ruf"),
        "rua": parts.get("rua"),
        "pct": parts.get("pct", "100"),
        "adkim": parts.get("adkim", "r"),
        "aspf": parts.get("aspf", "r"),
    }


def resolves_to_address(name, qtype="A", server=None):
    """
    True ONLY if a genuine address record is returned in the ANSWER section.

    Do not use `values()` for existence checks: a negative answer can carry an
    SOA in the authority section, and a CNAME chain can make a name appear to
    resolve when the target record type is absent.
    """
    r = query(name, qtype, server=server)
    if r.get("rcode") != 0:
        return False
    return any(a["type"] == qtype for a in r.get("answers", []))


def detect_wildcard(domain, server=None, probes=2):
    """
    Detect wildcard DNS by querying names that cannot legitimately exist.

    This is essential for subdomain review. With a wildcard in place (very common:
    Cloudflare, Vercel, Heroku, parking pages, and any catch-all host), EVERY
    subdomain "resolves", so admin.example.com, dev.example.com and
    phpmyadmin.example.com all look like live hosts when they are not. Without
    this check a scan reports a wall of false positives.

    Returns (is_wildcard, evidence_name).
    """
    import random
    import string
    for _ in range(probes):
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        name = f"zz{token}nonexistent.{domain}"
        r = query(name, "A", server=server)
        if r.get("rcode") == 0 and any(a["type"] == "A" for a in r.get("answers", [])):
            return True, name
    return False, None


def cname_target(name, server=None):
    """Return the CNAME target if one exists in the answer section."""
    r = query(name, "CNAME", server=server)
    for a in r.get("answers", []):
        if a["type"] == "CNAME":
            return a["value"]
    return None
