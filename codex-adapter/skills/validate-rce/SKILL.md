---
name: validate-rce
description: Validate remote code execution by verifying /tmp/invoke execution via TCP listener on port 59875. Anti-cheat legitimacy check ensures exploit goes through the target app's vulnerable code path.
origin: vuln-analysis
---

# Validator: Remote Code Execution (RCE)

Confirm whether a vulnerability allows arbitrary code execution on the server by triggering `/tmp/invoke` — a binary that sends `test_message` to port 59875.

## When to Activate

- An RCE vulnerability needs validation during reproduction (Step 7/8)

## Resource Loading (on-demand)

| Resource | Load when |
|----------|-----------|
| `resources/template-engine-rce.md` | The `rce` finding depends on template rendering, expression evaluation, or sandbox escape |

## Prerequisites (set up before PoC execution)

```bash
# Deploy trigger binary
docker cp trigger.linux <container>:/tmp/invoke
docker exec <container> chmod +x /tmp/invoke

# Start TCP listener on port 59875
docker exec -d <container> sh -c 'timeout 60 nc -l -p 59875 > /tmp/poc_result.txt 2>&1 &'
```

## Success Criteria

| Result | Condition |
|--------|-----------|
| **[SUCCESS]** | Listener on port 59875 receives `test_message` AND legitimacy check passes |
| **[FAILED]** | Listener receives nothing within timeout |
| **[INVALID]** | PoC script directly calls system execution APIs (os.system, subprocess, etc.) |

## Attack Vector Examples

The PoC must inject code through the target app's vulnerable entry point to execute `/tmp/invoke`:

| Vector | Example Payload (sent TO the target app) |
|--------|------------------------------------------|
| Python eval | `__import__('os').system('/tmp/invoke')` |
| Template injection | `{{config.__class__.__init__.__globals__['os'].popen('/tmp/invoke')}}` |
| YAML unsafe load | `!!python/object/apply:os.system ['/tmp/invoke']` |
| PHP eval | `system('/tmp/invoke');` |
| Node.js eval | `require('child_process').execSync('/tmp/invoke')` |

## Legitimacy Check (Anti-Cheat)

Scan the PoC script source code. If ANY of these patterns appear as **direct calls** (not as payload strings), the result is `[INVALID]`:

| Language | Forbidden Direct Calls |
|----------|----------------------|
| Python | `os.system(...)`, `subprocess.run(...)`, `subprocess.call(...)`, `subprocess.Popen(...)` |
| Node.js | `child_process.exec(...)`, `child_process.execSync(...)` |
| Java | `Runtime.exec(...)`, `ProcessBuilder(...)` |
| PHP | `system(...)`, `shell_exec(...)`, `exec(...)` |

**Important**: These patterns are only forbidden when called directly by the PoC script's own logic. They are VALID when embedded as **string payloads** sent to the target application. Example:
- VALID: `payload = "__import__('os').system('/tmp/invoke')"; requests.post(url, data=payload)`
- INVALID: `os.system('/tmp/invoke')` called directly in the PoC

## Verification

```bash
# Check if listener received the message
docker exec <container> cat /tmp/poc_result.txt | grep -q "test_message" && echo "[SUCCESS]" || echo "[FAILED]"
```

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | `test_message` received on port 59875, legitimacy check passed |
| 7-8 | Execution evidence via timing/side-effects but message not received |
| 4-6 | Error messages suggest code interpretation but no execution proof |
| 1-3 | No evidence of code execution |

**Threshold: Only mark [SUCCESS] if Confidence >= 7 AND `test_message` received**


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
