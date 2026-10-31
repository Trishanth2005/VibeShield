"""VibeShield & MRU Agent HTTP Server.
Pure Python standard library implementation (no pip dependencies required).
Serves MRU Agent (/) and VibeShield Security Console (/shield).
Run: python server.py
"""
import json
import os
import base64
import secrets
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import db
import tools
import shield
import agent
import healing

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SANDBOX_PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox", "pages")
DEMO_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_files")

ADMIN_SESSIONS = set()
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin123"

PAGES = {
    "/": "mru.html",
    "/shield": "index.html",
    "/admin/login": "login.html",
    "/privacy": "privacy.html",
    "/terms": "terms.html"
}

MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB HTTP request ceiling

class VibeShieldRequestHandler(BaseHTTPRequestHandler):
    def _get_cookies(self):
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        for item in cookie_header.split(";"):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies

    def _is_admin_authenticated(self) -> bool:
        cookies = self._get_cookies()
        token = cookies.get("vs_admin_session")
        return bool(token and token in ADMIN_SESSIONS)

    def _send_bytes(self, data: bytes, content_type: str, status_code: int = 200):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload: any, status_code: int = 200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(body, "application/json; charset=utf-8", status_code)

    def _send_json_with_cookie(self, payload: any, cookie_str: str, status_code: int = 200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", cookie_str)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # Authentication protection for /shield
        if path == "/shield":
            if not self._is_admin_authenticated():
                self.send_response(302)
                self.send_header("Location", "/admin/login")
                self.end_headers()
                return

        if path == "/admin/login":
            if self._is_admin_authenticated():
                self.send_response(302)
                self.send_header("Location", "/shield")
                self.end_headers()
                return

        if path in ("/admin/logout", "/api/logout"):
            token = self._get_cookies().get("vs_admin_session")
            if token:
                ADMIN_SESSIONS.discard(token)
            self.send_response(302)
            self.send_header("Set-Cookie", "vs_admin_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax")
            self.send_header("Location", "/admin/login")
            self.end_headers()
            return

        if path == "/api/report/download":
            fmt = query.get("format", ["html"])[0].lower()
            content, ctype, fname = tools.get_report_file(fmt)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # Static Page Routing
        if path in PAGES:
            target_file = os.path.join(STATIC_DIR, PAGES[path])
            if os.path.exists(target_file):
                with open(target_file, "rb") as f:
                    return self._send_bytes(f.read(), "text/html; charset=utf-8")

        if path == "/favicon.svg":
            fav = os.path.join(STATIC_DIR, "favicon.svg")
            if os.path.exists(fav):
                with open(fav, "rb") as f:
                    return self._send_bytes(f.read(), "image/svg+xml")

        # API Endpoints
        if path == "/api/status":
            return self._send_json(agent.ollama_status())

        if path == "/api/state":
            return self._send_json(db.get_state())

        if path == "/api/threats":
            limit = int(query.get("limit", [100])[0])
            return self._send_json(db.get_incidents(limit=limit))

        if path == "/api/policies":
            stats = db.get_policy_stats()
            catalog = []
            for p in shield.POLICY_CATALOG:
                item = dict(p)
                p_stat = stats.get(p["id"], {"hits": 0, "last_hit": None})
                item["hits"] = p_stat["hits"]
                item["last_hit"] = p_stat["last_hit"]
                catalog.append(item)
            return self._send_json(catalog)

        if path == "/api/self_heal/status":
            return self._send_json(healing.get_integrity_status())

        if path == "/api/audit":
            if not self._is_admin_authenticated():
                return self._send_json({"error": "Unauthorized. Admin session required."}, 401)
            stage = query.get("stage", [None])[0]
            severity = query.get("severity", [None])[0]
            limit = int(query.get("limit", [200])[0])
            return self._send_json(db.get_audit_events(limit=limit, stage=stage, severity=severity))

        if path == "/api/history":
            limit = int(query.get("limit", [50])[0])
            return self._send_json({
                "incidents": db.get_incidents(limit=limit),
                "events": db.get_audit_events(limit=limit),
                "recovery": db.get_recovery_history(limit=limit),
                "timeline": db.get_trust_timeline()
            })

        if path == "/api/files":
            ws = tools.WORKSPACE
            items = []
            if os.path.exists(ws):
                for f in sorted(os.listdir(ws)):
                    full = os.path.join(ws, f)
                    if os.path.isfile(full):
                        items.append({
                            "name": f,
                            "size": os.path.getsize(full),
                            "mtime": os.path.getmtime(full)
                        })
            return self._send_json(items)

        # Sandbox Lab Pages Serving
        if path.startswith("/sandbox/pages/"):
            fname = os.path.basename(path)
            fpath = os.path.join(SANDBOX_PAGES_DIR, fname)
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    return self._send_bytes(f.read(), "text/html; charset=utf-8")
            return self._send_json({"error": "Sandbox page not found"}, 404)

        # Demo Test Files Serving
        if path.startswith("/demo_files/"):
            fname = os.path.basename(path)
            fpath = os.path.join(DEMO_FILES_DIR, fname)
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    return self._send_bytes(f.read(), "text/plain; charset=utf-8")
            return self._send_json({"error": "Demo file not found"}, 404)

        self._send_json({"error": f"Endpoint not found: {path}"}, 404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_BODY_SIZE:
            return self._send_json({"error": "Payload exceeds maximum allowable size (10 MB)"}, 413)

        raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception:
            body = {}

        if self.path == "/admin/login":
            username = ""
            password = ""
            content_type = self.headers.get("Content-Type", "")
            if "application/json" in content_type:
                username = str(body.get("username", "")).strip()
                password = str(body.get("password", "")).strip()
            else:
                try:
                    form_data = parse_qs(raw_body.decode("utf-8"))
                    username = form_data.get("username", [""])[0].strip()
                    password = form_data.get("password", [""])[0].strip()
                except Exception:
                    pass

            if not username and isinstance(body, dict):
                username = str(body.get("username", "")).strip()
                password = str(body.get("password", "")).strip()

            if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                token = secrets.token_hex(24)
                ADMIN_SESSIONS.add(token)
                cookie_val = f"vs_admin_session={token}; Path=/; HttpOnly; SameSite=Lax"
                if "application/json" in content_type or "application/json" in self.headers.get("Accept", ""):
                    return self._send_json_with_cookie({"status": "success", "redirect": "/shield"}, cookie_val, 200)
                else:
                    self.send_response(302)
                    self.send_header("Set-Cookie", cookie_val)
                    self.send_header("Location", "/shield")
                    self.end_headers()
                    return
            else:
                if "application/json" in content_type or "application/json" in self.headers.get("Accept", ""):
                    return self._send_json({"error": "Invalid username or password"}, 401)
                else:
                    self.send_response(302)
                    self.send_header("Location", "/admin/login?error=Invalid%20username%20or%20password")
                    self.end_headers()
                    return

        if self.path == "/api/run":
            task = body.get("task", "")
            enforcement_mode = body.get("enforcement_mode")
            if not enforcement_mode:
                enforcement_mode = "enforce" if body.get("shield_on", True) else "audit"
            self_healing = bool(body.get("self_healing", True))
            chat = body.get("chat", [])
            files = body.get("files", [])
            result = agent.run(
                task=task,
                enforcement_mode=enforcement_mode,
                self_healing=self_healing,
                chat=chat,
                files=files
            )
            return self._send_json(result)

        if self.path == "/api/upload":
            file_name = body.get("name", "")
            b64_data = body.get("data", "")
            try:
                raw_bytes = base64.b64decode(b64_data)
                saved_name = tools.save_upload(file_name, raw_bytes)
                return self._send_json({
                    "name": saved_name,
                    "size": len(raw_bytes),
                    "status": "uploaded"
                })
            except ValueError as e:
                return self._send_json({"error": str(e)}, 400)
            except Exception as e:
                return self._send_json({"error": f"Upload processing error: {e}"}, 500)

        if self.path == "/api/self_heal/restore":
            if not self._is_admin_authenticated():
                return self._send_json({"error": "Unauthorized. Admin session required."}, 401)
            res = healing.heal(trigger_threat="Manual Operator Restoration")
            return self._send_json({
                "status": "success",
                "recovery": res,
                "integrity": healing.get_integrity_status(),
                "state": db.get_state()
            })

        if self.path == "/api/self_heal/toggle":
            if not self._is_admin_authenticated():
                return self._send_json({"error": "Unauthorized. Admin session required."}, 401)
            enabled = bool(body.get("enabled", True))
            db.set_self_healing(enabled)
            return self._send_json(db.get_state())

        if self.path == "/api/enforcement/toggle":
            if not self._is_admin_authenticated():
                return self._send_json({"error": "Unauthorized. Admin session required."}, 401)
            mode = body.get("mode", "enforce")
            db.set_enforcement_mode(mode)
            return self._send_json(db.get_state())

        if self.path == "/api/reset":
            if not self._is_admin_authenticated():
                return self._send_json({"error": "Unauthorized. Admin session required."}, 401)
            db.reset()
            tools.seed()
            return self._send_json({
                "status": "reset_completed",
                "state": db.get_state(),
                "integrity": healing.get_integrity_status()
            })

        self._send_json({"error": f"Endpoint not found: {self.path}"}, 404)

    def log_message(self, format, *args):
        # Concise logging format for development
        pass

def start_server(port: int = None):
    if port is None:
        port = int(os.environ.get("PORT", 8000))
    db.init()
    tools.seed()
    server_address = ("0.0.0.0", port)
    httpd = ThreadingHTTPServer(server_address, VibeShieldRequestHandler)
    print("=" * 60)
    print(f"  VibeShield Runtime Security & MRU Agent Server Active")
    print(f"  MRU Agent Console:             http://localhost:{port}/")
    print(f"  VibeShield Security Dashboard: http://localhost:{port}/shield")
    print(f"  Privacy Policy:                http://localhost:{port}/privacy")
    print(f"  Terms and Conditions:          http://localhost:{port}/terms")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server gracefully.")
        httpd.server_close()

if __name__ == "__main__":
    start_server()
