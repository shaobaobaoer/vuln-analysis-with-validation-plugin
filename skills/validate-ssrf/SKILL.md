---
name: validate-ssrf
description: Validate SSRF by injecting internal URLs to make the server connect to a local TCP listener on port 59876. Anti-cheat ensures the connection originates from the server, not the PoC script.
origin: vuln-analysis
---

# Validator: Server-Side Request Forgery (SSRF)

Confirm whether a vulnerability allows making the server send requests to internal destinations, verified by a TCP listener on port 59876.

## When to Activate

- An SSRF vulnerability needs validation during reproduction (Step 7/8)

## Prerequisites (set up before PoC execution)

```bash
# Start TCP listener on port 59876 (SSRF-specific)
docker exec -d <container> sh -c 'timeout 60 nc -l -p 59876 > /tmp/ssrf_result.txt 2>&1 &'
```

## Success Criteria

| Result | Condition |
|--------|-----------|
| **[SUCCESS]** | Listener on port 59876 receives any TCP connection AND legitimacy check passes |
| **[FAILED]** | Listener receives nothing within timeout |
| **[INVALID]** | PoC script itself connects to 127.0.0.1:59876 instead of making the server do it |

## Attack Vector Examples

The PoC must inject an internal URL through the target app's vulnerable parameter to make the **server** connect to the listener:

| Technique | Payload Example |
|-----------|----------------|
| Direct | `http://127.0.0.1:59876` |
| Localhost | `http://localhost:59876` |
| IPv6 loopback | `http://[::1]:59876` |
| Hex IP | `http://0x7f000001:59876` |
| Decimal IP | `http://2130706433:59876` |
| Zero IP | `http://0.0.0.0:59876` |
| DNS rebinding | Custom domain resolving to 127.0.0.1 |

## Legitimacy Check (Anti-Cheat)

Scan the PoC script source code. The result is `[INVALID]` if:

- The PoC script itself makes a request to `127.0.0.1:59876` or `localhost:59876`
- The PoC script opens a TCP socket to port 59876
- Any `requests.get("http://127.0.0.1:59876")` or equivalent called directly (not as a payload string passed to the target app)

**Rule**: The internal URL must be sent as a **parameter value** to the target application, which then makes the outbound request. The PoC only sends requests to the target app's public endpoint.

Example:
- VALID: `requests.post(target_url, data={"url": "http://127.0.0.1:59876"})` — URL injected as parameter
- INVALID: `requests.get("http://127.0.0.1:59876")` — PoC directly connects

## Verification

```bash
# Check if listener received any connection
result=$(docker exec <container> cat /tmp/ssrf_result.txt 2>/dev/null)
[ -n "$result" ] && echo "[SUCCESS]" || echo "[FAILED]"
```

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | Listener receives connection from the server, verified via connection log |
| 7-8 | Response contains internal service data (metadata endpoint, internal page) |
| 4-6 | URL is fetched but content is stripped; only timing differences |
| 1-3 | No evidence of outbound request |

**Threshold: Only mark [SUCCESS] if Confidence >= 7 AND listener received connection**

## Hard Exclusions

- SSRF controlling only the **path** (not host/protocol) is NOT a vulnerability
- SSRF in client-side JS/TS is NOT valid (can't bypass firewalls from client)


## Output: Write to results.json (MANDATORY)

After validation, write the result using the **canonical schema** (see `skills/poc-writer/SKILL.md §results.json Schema`). The `validation_result` object MUST contain exactly two fields: `marker` and `evidence`. Do NOT add extra keys.

```json
{
  "vuln_id": "VULN-001",
  "type": "<type>",
  "poc_script": "poc_scripts/poc_<type>_001.py",
  "status": "SUCCESS",
  "exit_code": 0,
  "retries": 0,
  "entry_point_used": "<entry point used>",
  "validation_result": {
    "marker": "CONFIRMED",
    "evidence": "<one sentence: what specific proof was observed — e.g., TCP listener received test_message, file /tmp/flag was written, etc.>"
  }
}
```

**Marker values**:
- `"CONFIRMED"` → success condition met AND legitimacy check passed
- `"NOT_REPRODUCED"` → no proof observed within timeout
- `"PARTIAL"` → partial evidence (e.g., server error but no marker file)
- `"ERROR"` → validation infrastructure failure

**FORBIDDEN**: Adding extra keys to `validation_result` (e.g., `anti_cheat`, `legitimacy_check`, `marker_found`, `inotify_verified`, `method`, `details`, `type`, `exit_code` inside `validation_result`). Put ALL evidence in the `evidence` string. Observed: 150+ different extra key names used across 175 production runs — none of them are valid.
