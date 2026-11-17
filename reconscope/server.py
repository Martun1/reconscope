"""A tiny local web server for the ReconScope GUI — standard library only.

It serves the static front-end from ../web and exposes one JSON endpoint,
GET /api/scan?domain=<d>&demo=<0|1>. It binds to 127.0.0.1 so the GUI is only
reachable from this machine. No framework, no dependencies.
"""
from __future__ import annotations

import json
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .engine import scan

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
_MIME = {".html": "text/html", ".js": "application/javascript", ".css": "text/css",
         ".svg": "image/svg+xml", ".ico": "image/x-icon", ".json": "application/json"}


class Handler(BaseHTTPRequestHandler):
    server_version = "ReconScope"

    def log_message(self, *a):  # keep the console quiet
        pass

    def _send(self, code, body: bytes, ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            return self._api_scan(parse_qs(parsed.query))
        path = parsed.path
        if path in ("/", ""):
            path = "/index.html"
        return self._serve_static(path)

    def _api_scan(self, qs):
        domain = (qs.get("domain", [""])[0]).strip()
        demo = qs.get("demo", ["0"])[0] in ("1", "true", "yes")
        if not domain:
            return self._send(400, json.dumps({"error": "missing domain"}).encode(), "application/json")
        try:
            report = scan(domain, demo=demo)
            body = json.dumps(report.to_dict(), ensure_ascii=False).encode("utf-8")
            return self._send(200, body, "application/json")
        except ValueError as e:
            return self._send(400, json.dumps({"error": str(e)}).encode(), "application/json")
        except Exception as e:  # noqa: BLE001
            return self._send(500, json.dumps({"error": f"scan failed: {e}"}).encode(), "application/json")

    def _serve_static(self, path):
        # prevent path traversal
        safe = os.path.normpath(path).lstrip("/\\")
        full = os.path.join(WEB_DIR, safe)
        if not full.startswith(WEB_DIR) or not os.path.isfile(full):
            return self._send(404, b"not found")
        ext = os.path.splitext(full)[1]
        with open(full, "rb") as f:
            self._send(200, f.read(), _MIME.get(ext, "application/octet-stream"))


def serve(port: int = 8787, open_browser: bool = True):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"ReconScope GUI running at {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping ReconScope.")
        httpd.shutdown()
