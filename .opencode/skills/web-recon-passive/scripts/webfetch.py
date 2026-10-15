"""
webfetch.py — polite HTTP client built on urllib, with rate limiting.

Design rules baked in here (these are what keep the tool passive):
  * A global request budget and inter-request delay. Recon that hammers a small
    shared host is both rude and likely to get your IP blocked.
  * An honest User-Agent that identifies the tool and gives a contact address,
    so an operator reading their logs knows what happened and can reach you.
  * No redirect following unless explicitly asked (you usually want to see the
    raw 301 and its Location header).
  * Response bodies are size-capped so a huge download cannot exhaust memory.

Everything here is what a browser does when you load a page. There is no
scanning, fuzzing, or exploitation code in this skill.
"""

import gzip
import io
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY_BYTES = 25 * 1024 * 1024  # 25 MB cap per response


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


class Client:
    """Rate-limited HTTP client with a hard request budget."""

    def __init__(self, contact_email="researcher@example.com", tool_name="passive-recon",
                 delay=0.7, budget=400, timeout=20, verify_tls=True):
        self.delay = delay
        self.budget = budget
        self.used = 0
        self.timeout = timeout
        self.contact_email = contact_email
        self.ua = (f"{tool_name}/1.0 (passive security review; +contact {contact_email}) "
                   f"Mozilla/5.0 (compatible)")
        self._last = 0.0
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        self.history = []

    # -- budget / politeness -------------------------------------------------
    def _throttle(self):
        if self.used >= self.budget:
            raise RuntimeError(
                f"Request budget of {self.budget} exhausted. Raise --max-requests "
                f"only if you have authorization to generate that much traffic.")
        wait = self.delay - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        self.used += 1

    # -- core request --------------------------------------------------------
    def request(self, url, method="GET", headers=None, follow=False, body=None):
        """Return a Response-ish dict. Never raises for HTTP errors."""
        self._throttle()
        hdrs = {"User-Agent": self.ua, "Accept": "*/*", "Accept-Language": "en",
                "Accept-Encoding": "gzip"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
        handlers = [urllib.request.HTTPSHandler(context=self._ctx)]
        if not follow:
            handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        started = time.monotonic()
        try:
            resp = opener.open(req, timeout=self.timeout)
            raw = resp.read(MAX_BODY_BYTES)
            status, hdrs_out, final_url = resp.status, dict(resp.headers), resp.geturl()
        except urllib.error.HTTPError as exc:
            raw = b""
            try:
                raw = exc.read(MAX_BODY_BYTES)
            except Exception:  # noqa: BLE001
                pass
            status, hdrs_out, final_url = exc.code, dict(exc.headers or {}), url
        except Exception as exc:  # noqa: BLE001
            record = {"url": url, "method": method, "status": None,
                      "error": f"{type(exc).__name__}: {exc}",
                      "elapsed_ms": int((time.monotonic() - started) * 1000)}
            self.history.append(record)
            return record

        if (hdrs_out.get("Content-Encoding") or "").lower() == "gzip":
            try:
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read(MAX_BODY_BYTES)
            except Exception:  # noqa: BLE001 - not actually gzip, keep raw
                pass

        elapsed = int((time.monotonic() - started) * 1000)
        record = {"url": url, "method": method, "status": status, "headers": hdrs_out,
                  "final_url": final_url, "size": len(raw), "elapsed_ms": elapsed}
        self.history.append(record)
        return {**record, "body": raw}

    def get(self, url, **kw):
        return self.request(url, "GET", **kw)

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def header(headers, name):
        """Case-insensitive header lookup."""
        if not headers:
            return None
        low = name.lower()
        for key, val in headers.items():
            if key.lower() == low:
                return val
        return None

    @staticmethod
    def all_headers(headers, name):
        """All values for a repeated header (e.g. Set-Cookie)."""
        if not headers:
            return []
        low = name.lower()
        return [v for k, v in headers.items() if k.lower() == low]


def normalise(target: str) -> dict:
    """Split a target URL into scheme/host/port and derive the registrable host."""
    if "://" not in target:
        target = "https://" + target
    parts = urllib.parse.urlsplit(target)
    host = parts.hostname or ""
    scheme = parts.scheme or "https"
    port = parts.port or (443 if scheme == "https" else 80)
    base = f"{scheme}://{host}" + ("" if parts.port is None else f":{parts.port}")
    # registrable domain: naive last-two-labels; good enough for recon, and the
    # caller can override with --domain for ccTLD/second-level cases like co.uk
    labels = host.split(".")
    domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
    return {"target": target, "base": base, "scheme": scheme, "host": host,
            "port": port, "domain": domain, "path": parts.path or "/"}


def resolves(host: str):
    """Does this hostname have an address at all? Used to gate network work."""
    try:
        socket.gethostbyname(host)
        return True
    except Exception:  # noqa: BLE001
        return False
