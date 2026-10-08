"""Tiny stand-in business app. It only shows who the proxy says you are."""
import os
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer

APP_NAME = os.environ.get("APP_NAME", "App")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        user = self.headers.get("X-Forwarded-Preferred-Username") or self.headers.get("X-Forwarded-User", "unknown")
        email = self.headers.get("X-Forwarded-Email", "unknown")
        body = (
            f"<html><body style='font-family:sans-serif;max-width:600px;margin:3rem auto'>"
            f"<h1>{escape(APP_NAME)}</h1>"
            f"<p>Access granted. The zero trust proxy verified you as "
            f"<b>{escape(user)}</b> ({escape(email)}).</p>"
            f"<p><a href='/oauth2/sign_out'>Sign out</a></p>"
            f"</body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"[{APP_NAME}] {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
