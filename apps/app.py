"""NovaBank demo app: mock banking actions checked by OPA on every request."""
import json
import os
from datetime import datetime
from decimal import Decimal, InvalidOperation
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.error import URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen

APP_NAME = os.environ.get("APP_NAME", "NovaBank")
APP_RESOURCE = os.environ.get("APP_RESOURCE", "unknown")
OPA_URL = os.environ.get("OPA_URL", "http://opa:8181/v1/data/zerogate/authz/allow")
RISK_URL = os.environ.get("RISK_URL", "http://risk-engine:8090")

# Fake, in-memory data for the classroom demo. No real money or accounts exist.
balance = Decimal("24680.50")
transactions = [
    {"when": "Today, 09:42", "name": "Northstar Cloud", "kind": "Software", "amount": Decimal("-249.00"), "status": "Completed"},
    {"when": "Today, 08:15", "name": "Client payment", "kind": "Incoming", "amount": Decimal("1850.00"), "status": "Completed"},
    {"when": "Yesterday", "name": "Metro Office", "kind": "Facilities", "amount": Decimal("-420.00"), "status": "Completed"},
]
ledger_lock = Lock()


def api_json(url, payload=None):
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST" if body is not None else "GET",
    )
    with urlopen(request, timeout=3) as response:
        return json.loads(response.read().decode("utf-8"))


def risk_state(user):
    result = api_json(f"{RISK_URL}/score?{urlencode({'user': user})}")
    score = result.get("score")
    if not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("Risk service returned an invalid score")
    return result


def policy_allows(user, roles, action, score):
    result = api_json(OPA_URL, {
        "input": {
            "user": {"name": user, "roles": roles},
            "resource": APP_RESOURCE,
            "action": action,
            "trust_score": score,
        }
    })
    allowed = result.get("result") is True
    if allowed:
        reason = "Required role, action, and risk score passed"
    elif score < 60:
        reason = "Risk score is below the required 60"
    elif APP_RESOURCE in {"hr", "finance"} and APP_RESOURCE not in roles:
        reason = f"Required {APP_RESOURCE} role is missing"
    else:
        reason = "Action is not permitted for this resource"
    api_json(f"{RISK_URL}/audit", {
        "user": user,
        "roles": roles,
        "resource": APP_RESOURCE,
        "action": action,
        "trust_score": score,
        "decision": "allow" if allowed else "deny",
        "reason": reason,
    })
    return allowed


def signal_device_unsafe(user):
    return api_json(f"{RISK_URL}/signal", {"user": user, "event": "device_unsafe"})


def audit_events(user, limit=8):
    query = urlencode({"user": user, "limit": limit})
    result = api_json(f"{RISK_URL}/audit?{query}")
    events = result.get("events", [])
    return events if isinstance(events, list) else []


def money(value):
    return f"${value:,.2f}"


CSS = """
:root{--ink:#18231f;--muted:#74817b;--line:#e7ece8;--paper:#f6f8f6;--green:#167b5a;--mint:#e9f5ef;--navy:#152822;--amber:#fff3dc;--red:#a53832}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 Inter,Segoe UI,Arial,sans-serif}
.shell{min-height:100vh;display:grid;grid-template-columns:238px 1fr}.side{background:var(--navy);color:#d8e5df;padding:26px 18px;display:flex;flex-direction:column;gap:32px}.brand{font-weight:800;font-size:19px;letter-spacing:.02em;color:white}.brand-mark{display:inline-grid;place-items:center;width:31px;height:31px;margin-right:9px;border-radius:10px;background:#65c59c;color:#12382a}.side-label{font-size:10px;letter-spacing:.16em;color:#93aaa0;margin:12px 10px 5px}.nav a{display:block;color:#c7d7d0;text-decoration:none;padding:11px 12px;border-radius:10px;margin:3px 0}.nav a.active,.nav a:hover{background:#284138;color:white}.side-note{margin-top:auto;border:1px solid #385247;background:#20372e;border-radius:13px;padding:14px;font-size:12px;color:#b9cbc3}.side-note b{display:block;color:#f1f7f3;margin-bottom:4px}
.main{padding:28px clamp(20px,4vw,56px) 56px;max-width:1420px;width:100%;margin:auto}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:34px}.crumb{font-size:12px;color:var(--muted)}.profile{display:flex;align-items:center;gap:10px}.avatar{width:38px;height:38px;border-radius:50%;display:grid;place-items:center;background:#dcece4;color:#176548;font-weight:700}.profile small{display:block;color:var(--muted);font-size:12px}.secure{background:var(--mint);color:#176548;border-radius:99px;padding:8px 12px;font-size:12px;font-weight:700}.hello{display:flex;align-items:end;justify-content:space-between;margin-bottom:24px}.hello h1{font-size:28px;letter-spacing:-.03em;margin:3px 0}.hello p{margin:0;color:var(--muted)}.date{font-size:12px;color:var(--muted)}
.grid{display:grid;gap:16px}.stats{grid-template-columns:repeat(3,minmax(0,1fr));margin-bottom:18px}.card{background:white;border:1px solid var(--line);border-radius:16px;padding:20px;box-shadow:0 4px 14px #1e39270a}.stat-label{font-size:12px;color:var(--muted);display:flex;justify-content:space-between}.stat-value{font-size:27px;font-weight:750;letter-spacing:-.04em;margin:11px 0 4px}.trend{font-size:12px;color:var(--green)}.overview{grid-template-columns:minmax(0,1.55fr) minmax(300px,.85fr);align-items:start}.section-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:15px}.section-head h2{font-size:16px;margin:0}.section-head a{color:var(--green);font-size:12px;text-decoration:none}.security{background:#fbfdfb}.score-row{display:flex;align-items:center;justify-content:space-between;margin:16px 0 8px}.score{font-size:25px;font-weight:750}.status{font-size:11px;background:var(--mint);color:var(--green);padding:5px 9px;border-radius:99px;font-weight:700}.status.flagged{background:#fdecea;color:var(--red)}.bar{height:8px;border-radius:20px;background:#e8efeb;overflow:hidden}.bar span{display:block;height:100%;border-radius:20px;background:#36a678}.device{color:var(--muted);font-size:12px;margin:13px 0}.event{border-top:1px solid var(--line);padding-top:12px;margin-top:13px;color:var(--muted);font-size:12px}.event strong{color:var(--ink)}
.btn{border:0;border-radius:10px;padding:11px 15px;background:var(--green);color:white;font-weight:700;cursor:pointer}.btn:hover{background:#11674b}.btn-outline{background:white;color:var(--ink);border:1px solid var(--line)}.btn-risk{background:#fff3dc;color:#80520a;border:1px solid #f2dfb9;margin-top:14px;width:100%}.btn-risk:hover{background:#f9e8c5}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field label{display:block;font-size:11px;color:var(--muted);margin-bottom:5px}.field input,.field select{width:100%;height:42px;border:1px solid #dfe7e2;border-radius:9px;padding:0 11px;background:white;color:var(--ink);font:inherit}.field.full{grid-column:1/-1}.transfer-note{font-size:11px;color:var(--muted);margin:10px 0 0}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;text-align:left}th{font-size:10px;letter-spacing:.09em;text-transform:uppercase;color:#8b9791;padding:10px 8px;border-bottom:1px solid var(--line)}td{padding:13px 8px;border-bottom:1px solid #f0f3f1;font-size:12px}td:last-child,th:last-child{text-align:right}.merchant{font-weight:650;font-size:13px}.sub{font-size:11px;color:var(--muted)}.positive{color:var(--green);font-weight:700}.negative{font-weight:700}.lower{margin-top:18px}.columns{grid-template-columns:minmax(0,1.2fr) minmax(300px,.8fr)}.pill{font-size:10px;color:#61736a;background:#f1f5f2;border-radius:99px;padding:5px 8px}
.decision{font-size:10px;font-weight:750;border-radius:99px;padding:4px 8px;white-space:nowrap}.decision-allow{background:#e9f5ef;color:#176548}.decision-deny{background:#fdecea;color:#a53832}.decision-signal{background:#fff3dc;color:#80520a}.audit-reason{display:block;color:var(--muted);font-size:10px;margin-top:3px}
.banner{max-width:760px;margin:10vh auto;background:white;border:1px solid var(--line);border-radius:20px;padding:36px;box-shadow:0 16px 50px #1e392710}.banner h1{margin:0 0 10px}.banner p{color:var(--muted)}.banner-deny{border-top:4px solid var(--red)}.banner-success{border-top:4px solid var(--green)}.metric{font-size:28px;font-weight:800}.alert{background:var(--amber);border:1px solid #f2dfb9;border-radius:12px;padding:14px;margin:18px 0;color:#6c4a14}.footer{text-align:center;font-size:10px;color:#97a29c;padding:24px}
@media(max-width:900px){.shell{grid-template-columns:1fr}.side{padding:14px 18px;gap:10px}.nav{display:flex;overflow:auto}.side-label,.side-note{display:none}.nav a{white-space:nowrap}.overview,.columns{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}}
@media(max-width:560px){.stats{grid-template-columns:1fr}.hello{display:block}.date{margin-top:10px}.main{padding:18px}.top{margin-bottom:24px}.form-grid{grid-template-columns:1fr}.field.full{grid-column:auto}}
"""


def page(content, title="NovaBank | Secure workspace"):
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{escape(title)}</title><style>{CSS}</style></head><body>{content}</body></html>")


def transfer_form(button="Review and send demo transfer"):
    return (
        "<form method='post' action='/transfer'><div class='form-grid'>"
        "<div class='field'><label for='recipient'>SEND TO</label><select id='recipient' name='recipient' required>"
        "<option value='Maya Patel'>Maya Patel · Operations</option>"
        "<option value='Cloudline Services'>Cloudline Services · Vendor</option>"
        "<option value='Jordan Lee'>Jordan Lee · Payroll</option></select></div>"
        "<div class='field'><label for='amount'>AMOUNT (USD)</label><input id='amount' name='amount' type='number' min='1' max='5000' step='0.01' placeholder='250.00' required></div>"
        "<div class='field full'><label for='memo'>NOTE</label><input id='memo' name='memo' maxlength='80' placeholder='What is this transfer for?'></div>"
        f"<div class='field full'><button class='btn' type='submit'>{escape(button)} →</button></div>"
        "</div><p class='transfer-note'>Demo only: this updates a fake balance in this container. No real payment is sent.</p></form>"
    )


def render_rows():
    with ledger_lock:
        rows = list(transactions[:6])
    if not rows:
        return "<tr><td colspan='4'>No demo activity yet.</td></tr>"
    rendered = []
    for item in rows:
        amount = item["amount"]
        cls = "positive" if amount >= 0 else "negative"
        prefix = "+" if amount >= 0 else "−"
        rendered.append(
            "<tr>"
            f"<td><span class='merchant'>{escape(item['name'])}</span><br><span class='sub'>{escape(item['kind'])}</span></td>"
            f"<td>{escape(item['when'])}</td><td><span class='pill'>{escape(item['status'])}</span></td>"
            f"<td class='{cls}'>{prefix}{money(abs(amount))}</td></tr>"
        )
    return "".join(rendered)


def render_audit(events):
    if not events:
        return "<tr><td colspan='5'>No policy decisions recorded yet.</td></tr>"
    rows = []
    for event in events:
        decision = str(event.get("decision", "unknown"))
        safe_decision = decision if decision in {"allow", "deny", "signal"} else "deny"
        rows.append(
            "<tr>"
            f"<td>{escape(str(event.get('timestamp', '')))}</td>"
            f"<td><strong>{escape(str(event.get('action', '')))}</strong>"
            f"<span class='audit-reason'>{escape(str(event.get('reason', '')))}</span></td>"
            f"<td>{escape(str(event.get('resource', '')))}</td>"
            f"<td>{escape(str(event.get('trust_score', '')))} / 100</td>"
            f"<td><span class='decision decision-{safe_decision}'>{escape(decision.upper())}</span></td>"
            "</tr>"
        )
    return "".join(rows)


def audit_card(events):
    return (
        "<section class='card lower' id='security-log'><div class='section-head'>"
        "<h2>Recent access decisions</h2><span class='pill'>AUDIT TRAIL</span></div>"
        "<div class='table-wrap'><table><thead><tr><th>TIME (UTC)</th><th>ACTION / REASON</th>"
        "<th>RESOURCE</th><th>RISK SCORE</th><th>DECISION</th></tr></thead>"
        f"<tbody>{render_audit(events)}</tbody></table></div>"
        "<p class='transfer-note'>Showing your latest policy decisions and simulated device signals.</p></section>"
    )


def security_card(user, state, show_simulation=False):
    score = state["score"]
    compliant = state.get("device_compliant", True)
    status = "DEVICE COMPLIANT" if compliant else "DEVICE FLAGGED"
    status_cls = "status" if compliant else "status flagged"
    event = state.get("last_event", "No risk signals recorded")
    simulation = (
        "<form method='post' action='/simulate-device-issue'>"
        "<button class='btn btn-risk' type='submit'>Simulate firewall being disabled</button></form>"
        "<p class='transfer-note'>This changes the device status and stored score used in the next policy decision.</p>"
        if show_simulation else ""
    )
    return (
        "<section class='card security'><div class='section-head'><h2>Access security</h2><span class='pill'>LIVE POLICY</span></div>"
        f"<div class='score-row'><span class='score'>{score}<span style='font-size:13px;color:#74817b'> / 100</span></span>"
        f"<span class='{status_cls}'>{status}</span></div>"
        f"<div class='bar'><span style='width:{score}%'></span></div>"
        f"<p class='device'>Signed in as <strong>{escape(user)}</strong>. Device signal: {escape('firewall active' if compliant else 'firewall disabled')}.</p>"
        f"<div class='event'>LATEST SIGNAL<br><strong>{escape(event)}</strong></div>"
        f"{simulation}</section>"
    )


def finance_dashboard(user, email, roles, state, events):
    with ledger_lock:
        current_balance = balance
    initials = escape((user[:1] or "U").upper())
    content = (
        "<div class='shell'><aside class='side'><div class='brand'><span class='brand-mark'>N</span>NOVABANK</div>"
        "<div><div class='side-label'>WORKSPACE</div><nav class='nav'>"
        "<a class='active' href='#overview'>⌂ &nbsp; Overview</a><a href='#payments'>↗ &nbsp; Payments</a>"
        "<a href='#activity'>▤ &nbsp; Activity</a><a href='#security'>◈ &nbsp; Security</a></nav></div>"
        "<div class='side-note'><b>Zero Trust is active</b>Every protected request is checked against your role and current risk score.</div></aside>"
        "<main class='main'><div class='top'><span class='crumb'>Workspace / Finance</span><div class='profile'>"
        "<span class='secure'>● &nbsp; VERIFIED SESSION</span>"
        f"<span class='avatar'>{initials}</span><span><strong>{escape(user)}</strong><small>{escape(email)}</small></span></div></div>"
        f"<section id='overview'><div class='hello'><div><div class='crumb'>{datetime.now().strftime('%A, %B %d').upper()}</div>"
        f"<h1>Good day, {escape(user).title()}</h1><p>Here’s your finance workspace at a glance.</p></div>"
        "<span class='date'>Demo account · USD</span></div>"
        "<div class='grid stats'>"
        f"<article class='card'><div class='stat-label'>AVAILABLE BALANCE <span>•••</span></div><div class='stat-value'>{money(current_balance)}</div><div class='trend'>↑ 4.8% <span style='color:#74817b'>from last month</span></div></article>"
        "<article class='card'><div class='stat-label'>INCOMING THIS MONTH <span>↙</span></div><div class='stat-value'>$8,420.00</div><div class='trend'>↑ 12.2% <span style='color:#74817b'>from last month</span></div></article>"
        "<article class='card'><div class='stat-label'>OUTGOING THIS MONTH <span>↗</span></div><div class='stat-value'>$3,186.40</div><div class='sub'>Across 18 demo transactions</div></article>"
        "</div></section>"
        "<div class='grid overview'><div class='grid'>"
        "<section class='card' id='payments'><div class='section-head'><h2>Make a transfer</h2><span class='pill'>Finance role required</span></div>"
        f"{transfer_form()}</section>"
        "<section class='card' id='activity'><div class='section-head'><h2>Recent activity</h2><a href='#activity'>View all</a></div>"
        "<div class='table-wrap'><table><thead><tr><th>DESCRIPTION</th><th>DATE</th><th>STATUS</th><th>AMOUNT</th></tr></thead>"
        f"<tbody>{render_rows()}</tbody></table></div></section></div>"
        f"<div id='security'>{security_card(user, state, show_simulation=True)}</div></div>"
        f"{audit_card(events)}"
        "<div class='footer'>NOVABANK DEMO · FAKE DATA ONLY · NO REAL TRANSACTIONS ARE SENT</div></main></div>"
    )
    return page(content)


def hr_dashboard(user, email, roles, state, events):
    initials = escape((user[:1] or "U").upper())
    content = (
        "<div class='shell'><aside class='side'><div class='brand'><span class='brand-mark'>N</span>NOVABANK</div>"
        "<div><div class='side-label'>WORKSPACE</div><nav class='nav'><a class='active' href='#overview'>⌂ &nbsp; Overview</a>"
        "<a href='#people'>♙ &nbsp; People</a><a href='#security'>◈ &nbsp; Security</a></nav></div>"
        "<div class='side-note'><b>Zero Trust is active</b>Every protected request is checked against your role and current risk score.</div></aside>"
        "<main class='main'><div class='top'><span class='crumb'>Workspace / People</span><div class='profile'>"
        "<span class='secure'>● &nbsp; VERIFIED SESSION</span>"
        f"<span class='avatar'>{initials}</span><span><strong>{escape(user)}</strong><small>{escape(email)}</small></span></div></div>"
        "<section id='overview'><div class='hello'><div><div class='crumb'>PEOPLE OPERATIONS</div>"
        f"<h1>Welcome, {escape(user).title()}</h1><p>Your employee workspace is protected by ZeroGate.</p></div></div>"
        "<div class='grid stats'><article class='card'><div class='stat-label'>LEAVE BALANCE</div><div class='stat-value'>12 days</div><div class='sub'>Available this year</div></article>"
        "<article class='card'><div class='stat-label'>NEXT PAY DAY</div><div class='stat-value'>Oct 15</div><div class='sub'>Payroll schedule</div></article>"
        "<article class='card'><div class='stat-label'>MY ROLE</div><div class='stat-value'>HR team</div><div class='sub'>Access limited by policy</div></article></div></section>"
        "<div class='grid overview'><section class='card' id='people'><div class='section-head'><h2>People resources</h2><span class='pill'>Sample content</span></div>"
        "<p>Employee directory</p><p>Leave requests</p><p>Payroll calendar</p></section>"
        f"<div id='security'>{security_card(user, state)}</div></div>"
        f"{audit_card(events)}"
        "<div class='footer'>NOVABANK DEMO · FAKE DATA ONLY · NO REAL EMPLOYEE RECORDS</div></main></div>"
    )
    return page(content)


def result_page(title, message, *, status=200, kind="success", extra=""):
    border = "banner-deny" if kind == "deny" else "banner-success"
    return page(
        f"<main class='banner {border}'><div class='brand'><span class='brand-mark'>N</span>NOVABANK</div>"
        f"<h1>{escape(title)}</h1><p>{message}</p>{extra}</main>",
        f"NovaBank | {title}",
    ), status


class Handler(BaseHTTPRequestHandler):
    def identity(self):
        user = self.headers.get("X-Forwarded-Preferred-Username") or self.headers.get("X-Forwarded-User", "unknown")
        email = self.headers.get("X-Forwarded-Email", "unknown")
        roles = [role.strip() for role in self.headers.get("X-Forwarded-Groups", "").split(",") if role.strip()]
        return user, email, roles

    def send_html(self, status, document):
        body = document.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def service_error(self, error):
        print(f"[{APP_NAME}] risk/OPA service unavailable: {error}", flush=True)
        document, status = result_page(
            "Access check unavailable",
            "ZeroGate could not reach a required security service. Access is blocked until it is available.",
            status=503,
            kind="deny",
        )
        self.send_html(status, document)

    def deny(self, user, score, *, transfer=False):
        print(f"[{APP_NAME}] DENY user={self.identity()[0]!r} resource={APP_RESOURCE!r} score={score}", flush=True)
        try:
            events = audit_events(user)
        except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
            events = []
        reason = "Policy requirements were not met"
        if events and events[0].get("decision") == "deny":
            reason = events[0].get("reason", reason)
        if transfer:
            title = "Transfer blocked"
            message = (f"OPA denied this transfer: {reason}. Current trust score: {score}/100. "
                       "No balance or transaction record was changed.")
        else:
            title = "Access paused by ZeroGate"
            message = (f"OPA denied this request: {reason}. Current trust score: {score}/100. "
                       "The request was blocked.")
        log_panel = audit_card(events) if events else ""
        extra = log_panel + "<p><a class='btn btn-outline' href='/oauth2/sign_out'>Sign out</a></p>"
        document, status = result_page(title, escape(message), status=403, kind="deny", extra=extra)
        self.send_html(status, document)

    def do_GET(self):
        if urlparse(self.path).path not in ("/", ""):
            self.send_error(404)
            return
        user, email, roles = self.identity()
        try:
            state = risk_state(user)
            allowed = policy_allows(user, roles, "read", state["score"])
            events = audit_events(user)
        except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as error:
            self.service_error(error)
            return
        if not allowed:
            self.deny(user, state["score"])
            return
        print(f"[{APP_NAME}] ALLOW user={user!r} roles={roles!r} score={state['score']}", flush=True)
        if APP_RESOURCE == "finance":
            document = finance_dashboard(user, email, roles, state, events)
        else:
            document = hr_dashboard(user, email, roles, state, events)
        self.send_html(200, document)

    def do_POST(self):
        global balance
        path = urlparse(self.path).path
        if path not in ("/transfer", "/simulate-device-issue"):
            self.send_error(404)
            return
        user, _, roles = self.identity()
        try:
            state = risk_state(user)
            action = "transfer" if path == "/transfer" else "simulate_device_issue"
            if not policy_allows(user, roles, action, state["score"]):
                self.deny(user, state["score"], transfer=path == "/transfer")
                return

            if path == "/simulate-device-issue":
                changed = signal_device_unsafe(user)
                score = changed.get("score", 0)
                extra = (
                    "<div class='alert'><strong>Device posture changed:</strong> the demo firewall is now marked off. "
                    f"Your score is {score}/100. This signal is stored by the risk service.</div>"
                    "<h2>Now try a transfer</h2>"
                    f"{transfer_form('Attempt transfer while device is unsafe')}"
                )
                document, status = result_page(
                    "Device signal recorded",
                    "This was a simulated device event. You are still signed in; the next action will be checked with the new score.",
                    extra=extra,
                )
                print(f"[{APP_NAME}] SIGNAL user={user!r} device_unsafe score={score}", flush=True)
                self.send_html(status, document)
                return

            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
            recipient = form.get("recipient", [""])[0].strip()
            memo = form.get("memo", [""])[0].strip()[:80]
            try:
                amount = Decimal(form.get("amount", [""])[0]).quantize(Decimal("0.01"))
            except (InvalidOperation, ValueError):
                amount = Decimal("0")
            if (recipient not in {"Maya Patel", "Cloudline Services", "Jordan Lee"}
                    or not amount.is_finite() or amount <= 0 or amount > 5000):
                document, status = result_page(
                    "Check the transfer details",
                    "Choose a listed demo recipient and enter an amount from $0.01 to $5,000.00.",
                    status=400,
                    kind="deny",
                    extra=f"<p><a href='/'>Return to the dashboard</a></p>",
                )
                self.send_html(status, document)
                return

            with ledger_lock:
                if amount > balance:
                    document, status = result_page(
                        "Not enough demo funds",
                        f"The available demo balance is {money(balance)}. No transfer was made.",
                        status=400,
                        kind="deny",
                        extra="<p><a href='/'>Return to the dashboard</a></p>",
                    )
                    self.send_html(status, document)
                    return
                balance -= amount
                transactions.insert(0, {
                    "when": datetime.now().strftime("Today, %H:%M"),
                    "name": recipient,
                    "kind": memo or "Demo transfer",
                    "amount": -amount,
                    "status": "Completed",
                })
            document, status = result_page(
                "Demo transfer completed",
                f"{money(amount)} was recorded as a mock transfer to {escape(recipient)}. No real payment was sent.",
                extra="<p><a class='btn' href='/'>Return to your dashboard</a></p>",
            )
            print(f"[{APP_NAME}] TRANSFER user={user!r} recipient={recipient!r} amount={amount}", flush=True)
            self.send_html(status, document)
        except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as error:
            self.service_error(error)

    def log_message(self, fmt, *args):
        print(f"[{APP_NAME}] {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
