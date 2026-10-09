"""Risk signals and a persistent decision audit trail for the local demo."""
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

scores = {}
device_compliance = {}
last_events = {}
DB_PATH = os.environ.get("AUDIT_DB_PATH", "/data/audit.db")


def connect_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=5)
    db.row_factory = sqlite3.Row
    return db


def initialize_db():
    with closing(connect_db()) as db:
        with db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    user TEXT NOT NULL,
                    roles TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    action TEXT NOT NULL,
                    trust_score INTEGER NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
            """)


def store_audit_event(event):
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    roles = event.get("roles", [])
    if not isinstance(roles, list):
        roles = []
    with closing(connect_db()) as db:
        with db:
            cursor = db.execute(
                """INSERT INTO audit_events
                   (timestamp, user, roles, resource, action, trust_score, decision, reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    timestamp,
                    event["user"],
                    ", ".join(str(role)[:80] for role in roles[:10]),
                    event["resource"],
                    event["action"],
                    event["trust_score"],
                    event["decision"],
                    event["reason"],
                ),
            )
            event_id = cursor.lastrowid
        return event_id, timestamp


def read_audit_events(user, limit):
    with closing(connect_db()) as db:
        rows = db.execute(
            """SELECT timestamp, user, roles, resource, action, trust_score, decision, reason
               FROM audit_events WHERE user = ? ORDER BY id DESC LIMIT ?""",
            (user, limit),
        ).fetchall()
    return [dict(row) for row in rows]


initialize_db()


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_payload(self):
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_json(200, {"ok": True})
            return

        query = parse_qs(parsed.query)
        user = query.get("user", [""])[0].strip().lower()
        if parsed.path == "/audit":
            if not user:
                self.send_json(400, {"error": "user is required"})
                return
            try:
                limit = max(1, min(int(query.get("limit", ["10"])[0]), 50))
                events = read_audit_events(user, limit)
            except (ValueError, sqlite3.Error) as error:
                self.send_json(400, {"error": f"invalid audit request: {error}"})
                return
            self.send_json(200, {"user": user, "events": events})
            return

        if parsed.path != "/score":
            self.send_json(404, {"error": "not found"})
            return
        if not user:
            self.send_json(400, {"error": "user is required"})
            return
        self.send_json(200, {
            "user": user,
            "score": scores.setdefault(user, 100),
            "device_compliant": device_compliance.setdefault(user, True),
            "last_event": last_events.get(user, "No risk signals recorded"),
        })

    def do_POST(self):
        route = urlparse(self.path).path
        if route not in ("/signal", "/audit"):
            self.send_json(404, {"error": "not found"})
            return
        try:
            payload = self.read_payload()
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "send valid JSON"})
            return

        user = str(payload.get("user", "")).strip().lower()[:100]
        if not user:
            self.send_json(400, {"error": "user is required"})
            return

        if route == "/audit":
            score = payload.get("trust_score")
            decision = str(payload.get("decision", ""))
            fields = {key: str(payload.get(key, "")).strip()[:160] for key in ("resource", "action", "reason")}
            if (not isinstance(score, int) or not 0 <= score <= 100
                    or decision not in {"allow", "deny", "signal"}
                    or not all(fields.values())):
                self.send_json(400, {"error": "user, resource, action, valid score, decision, and reason are required"})
                return
            try:
                event_id, timestamp = store_audit_event({
                    "user": user,
                    "roles": payload.get("roles", []),
                    **fields,
                    "trust_score": score,
                    "decision": decision,
                })
            except sqlite3.Error as error:
                self.send_json(503, {"error": f"audit storage unavailable: {error}"})
                return
            self.send_json(201, {"id": event_id, "timestamp": timestamp, "stored": True})
            return

        if payload.get("event") != "device_unsafe":
            self.send_json(400, {"error": "user and supported event are required"})
            return
        old_score = scores.setdefault(user, 100)
        new_score = max(0, old_score - 80)
        scores[user] = new_score
        device_compliance[user] = False
        last_events[user] = "Firewall disabled (simulated)"
        try:
            store_audit_event({
                "user": user,
                "roles": [],
                "resource": "finance",
                "action": "device_unsafe",
                "trust_score": new_score,
                "decision": "signal",
                "reason": "Firewall disabled (simulated)",
            })
        except sqlite3.Error as error:
            self.send_json(503, {"error": f"audit storage unavailable: {error}"})
            return
        print(f"RISK user={user!r} event=device_unsafe score={old_score}->{new_score}", flush=True)
        self.send_json(200, {"user": user, "event": "device_unsafe", "score": new_score})

    def log_message(self, fmt, *args):
        print(f"[risk-engine] {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
