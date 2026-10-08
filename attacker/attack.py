import socket
import urllib.error
import urllib.request

TARGETS = {
    "HR guard (hr-proxy, reachable from idp-net)": "http://hr-proxy:4180/",
    "Finance guard (finance-proxy, reachable from idp-net)": "http://finance-proxy:4180/",
}

UNREACHABLE = ["hr-app", "finance-app"]


def try_guard(name, url):
    print(f"\n[*] {name}")
    print(f"    requesting {url} with no login session...")
    try:
        resp = urllib.request.urlopen(url, timeout=6)
        body = resp.read(200).decode("utf-8", "replace")
        if "Access granted" in body:
            print("    !! UNEXPECTED: got app content without logging in")
        else:
            print(f"    -> HTTP {resp.status}, sent to login page (blocked)")
    except urllib.error.HTTPError as e:
        print(f"    -> HTTP {e.code} (blocked)")
    except Exception as e:
        print(f"    -> connection failed: {e} (blocked)")


def try_direct(name):
    print(f"\n[*] Trying to resolve '{name}' directly (skipping the guard)...")
    try:
        ip = socket.gethostbyname(name)
        print(f"    !! UNEXPECTED: resolved to {ip} - network isolation failed")
    except socket.gaierror:
        print("    -> name does not resolve from here (blocked: no network path)")


if __name__ == "__main__":
    print("=== Zero Trust lab: outsider-with-no-session demo ===")
    for name, url in TARGETS.items():
        try_guard(name, url)
    for host in UNREACHABLE:
        try_direct(host)
    print("\nDone. Compare this against the same requests on a flat/no-ZTA network.")