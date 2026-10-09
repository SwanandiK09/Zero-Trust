"""In-memory risk scores for the local ZeroGate coursework demonstration."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

scores = {}
device_compliance = {}
last_events = {}


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_json(200, {"ok": True})
            return
        if parsed.path != "/score":
            self.send_json(404, {"error": "not found"})
            return

        user = parse_qs(parsed.query).get("user", [""])[0].strip().lower()
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
        if urlparse(self.path).path != "/signal":
            self.send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "send valid JSON"})
            return

        user = str(payload.get("user", "")).strip().lower()
        event = payload.get("event")
        if not user or event != "device_unsafe":
            self.send_json(400, {"error": "user and supported event are required"})
            return

        old_score = scores.setdefault(user, 100)
        new_score = max(0, old_score - 80)
        scores[user] = new_score
        device_compliance[user] = False
        last_events[user] = "Firewall disabled (simulated)"
        print(f"RISK user={user!r} event=device_unsafe score={old_score}->{new_score}", flush=True)
        self.send_json(200, {"user": user, "event": event, "score": new_score})

    def log_message(self, fmt, *args):
        print(f"[risk-engine] {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
