"""Risk signals and a persistent decision audit trail for the local demo."""
import json
import hashlib
import hmac
import os
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

scores = {}
device_compliance = {}
last_events = {}
device_ids = {}
DB_PATH = os.environ.get("AUDIT_DB_PATH", "/data/audit.db")
POSTURE_SHARED_SECRET = os.environ.get("POSTURE_SHARED_SECRET", "lab-only-change-me")


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
                    device_id TEXT NOT NULL DEFAULT 'unknown',
                    roles TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    action TEXT NOT NULL,
                    trust_score INTEGER NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(audit_events)")}
            if "device_id" not in columns:
                db.execute("ALTER TABLE audit_events ADD COLUMN device_id TEXT NOT NULL DEFAULT 'unknown'")


def store_audit_event(event):
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    roles = event.get("roles", [])
    if not isinstance(roles, list):
        roles = []
    with closing(connect_db()) as db:
        with db:
            cursor = db.execute(
                """INSERT INTO audit_events
                   (timestamp, user, device_id, roles, resource, action, trust_score, decision, reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    timestamp,
                    event["user"],
                    str(event.get("device_id", "unknown"))[:100],
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
            """SELECT timestamp, user, device_id, roles, resource, action, trust_score, decision, reason
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

    def read_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def valid_posture_signature(self, timestamp, body):
        try:
            sent_at = int(timestamp)
            timestamp_bytes = timestamp.encode("ascii")
        except (TypeError, ValueError, UnicodeEncodeError):
            return False
        if abs(time.time() - sent_at) > 120:
            return False
        message = timestamp_bytes + b"." + body
        expected = hmac.new(POSTURE_SHARED_SECRET.encode("utf-8"), message, hashlib.sha256).hexdigest()
        supplied = self.headers.get("X-Posture-Signature", "")
        return hmac.compare_digest(expected, supplied)

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
            "score": scores.setdefault(user, 20),
            "device_compliant": device_compliance.setdefault(user, False),
            "device_id": device_ids.get(user, "Not enrolled"),
            "last_event": last_events.get(user, "Waiting for a posture-agent report"),
        })

    def do_POST(self):
        route = urlparse(self.path).path
        if route not in ("/posture", "/audit"):
            self.send_json(404, {"error": "not found"})
            return
        try:
            body = self.read_body()
            if route == "/posture" and not self.valid_posture_signature(
                    self.headers.get("X-Posture-Timestamp", ""), body):
                self.send_json(401, {"error": "invalid or expired posture signature"})
                return
            payload = json.loads(body.decode("utf-8"))
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
                    "device_id": str(payload.get("device_id", "unknown"))[:100],
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

        device_id = str(payload.get("device_id", "")).strip()[:100]
        firewall_enabled = payload.get("firewall_enabled")
        simulated = payload.get("simulated", False)
        if not device_id or not isinstance(firewall_enabled, bool) or not isinstance(simulated, bool):
            self.send_json(400, {"error": "user, device_id, firewall_enabled, and simulated status are required"})
            return
        new_score = 100 if firewall_enabled else 20
        device_ids[user] = device_id
        last_events[user] = (
            "LAB TEST ONLY: firewall-disabled override (not real device state)" if simulated and not firewall_enabled
            else "Firewall enabled (posture agent report)" if firewall_enabled
            else "Firewall disabled (posture agent report)"
        )
        scores[user] = new_score
        device_compliance[user] = firewall_enabled
        try:
            store_audit_event({
                "user": user,
                "device_id": device_id,
                "roles": [],
                "resource": "finance",
                "action": "posture_report",
                "trust_score": new_score,
                "decision": "signal",
                "reason": last_events[user],
            })
        except sqlite3.Error as error:
            self.send_json(503, {"error": f"audit storage unavailable: {error}"})
            return
        print(f"POSTURE user={user!r} device={device_id!r} firewall={firewall_enabled} score={new_score}", flush=True)
        self.send_json(200, {
            "user": user,
            "device_id": device_id,
            "firewall_enabled": firewall_enabled,
            "simulated": simulated,
            "score": new_score,
        })

    def log_message(self, fmt, *args):
        print(f"[risk-engine] {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
