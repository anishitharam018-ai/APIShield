"""Local HTTP server (127.0.0.1 only) serving the dashboard and JSON API."""
import json
import os
import re
from http.server import BaseHTTPRequestHandler

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html"), encoding="utf-8") as _fh:
    HTML = _fh.read()


# ----------------------------------------------------------------- http -----
AGENT = None  # set by apishield.py before the server starts
_EXTENSION_ORIGIN_RE = re.compile(r"^(chrome|moz|edge)-extension://[a-z0-9]+/?$", re.I)


class Handler(BaseHTTPRequestHandler):
    server_version = "APIShield"

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype, extra_headers=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' "
                         "https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; "
                         "img-src 'self' data:; frame-ancestors 'none'")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        if host not in ("127.0.0.1", "localhost"):
            return self._send(403, "Forbidden", "text/plain; charset=utf-8")
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            return self._send(200, HTML, "text/html; charset=utf-8")
        if path == "/api/state":
            with AGENT.lock:
                st = AGENT.state
            if st is None:
                return self._send(503, json.dumps({"error": "starting"}), "application/json")
            return self._send(200, json.dumps(st), "application/json")
        if path == "/api/scan":
            try:
                return self._send(200, json.dumps(AGENT.scan()), "application/json")
            except Exception as exc:
                return self._send(500, json.dumps({"error": str(exc)}), "application/json")
        return self._send(404, "Not found", "text/plain; charset=utf-8")

    def do_POST(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        if host not in ("127.0.0.1", "localhost"):
            return self._send(403, "Forbidden", "text/plain; charset=utf-8")
        path = self.path.split("?")[0]
        origin = self.headers.get("Origin") or self.headers.get("Referer") or ""
        is_ext_origin = bool(_EXTENSION_ORIGIN_RE.match(origin))
        extra = {}
        if path == "/api/extension":
            # Only the APIShield browser extension (or this page itself) may post here.
            if origin and not (is_ext_origin or re.match(r"^https?://(127\.0\.0\.1|localhost)(:\d+)?(/|$)", origin, re.I)):
                return self._send(403, json.dumps({"error": "cross-site request blocked"}), "application/json")
            if is_ext_origin:
                extra["Access-Control-Allow-Origin"] = origin
        else:
            if origin and not re.match(r"^https?://(127\.0\.0\.1|localhost)(:\d+)?(/|$)", origin, re.I):
                return self._send(403, json.dumps({"error": "cross-site request blocked"}), "application/json")
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}") if length else {}
        except Exception:
            return self._send(400, json.dumps({"error": "bad request body"}), "application/json")

        if path == "/api/extension":
            ok = AGENT.record_browser_event(payload)
            return self._send(200, json.dumps({"ok": ok}), "application/json", extra)
        return self._send(404, "Not found", "text/plain; charset=utf-8")

    def do_OPTIONS(self):
        origin = self.headers.get("Origin") or ""
        if self.path.split("?")[0] == "/api/extension" and _EXTENSION_ORIGIN_RE.match(origin):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()
