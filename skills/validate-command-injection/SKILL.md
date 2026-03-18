---
name: validate-command-injection
description: Validate command injection by injecting shell metacharacters to execute /tmp/invoke, verified via TCP listener on port 59875. Anti-cheat ensures injection goes through the target app's parameter.
origin: vuln-analysis
---

# Validator: Command Injection

Confirm whether a vulnerability allows injecting and executing arbitrary OS commands through shell metacharacter injection, verified by triggering `/tmp/invoke`.

## When to Activate

- A command injection vulnerability needs validation during reproduction (Step 7/8)

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
| **[INVALID]** | PoC script directly executes commands instead of injecting through the target app |

## Attack Vector Examples

The PoC must inject shell metacharacters through the target app's vulnerable parameter:

| Metacharacter | Payload Example |
|---------------|----------------|
| Semicolon | `; /tmp/invoke` |
| Pipe | `\| /tmp/invoke` |
| AND chain | `&& /tmp/invoke` |
| Backticks | `` `/tmp/invoke` `` |
| Command substitution | `$(/tmp/invoke)` |
| Newline | `%0a/tmp/invoke` |

## Legitimacy Check (Anti-Cheat)

Scan the PoC script source code. If ANY of these patterns appear as **direct calls** (not as payload strings), the result is `[INVALID]`:

- `os.system(...)`, `subprocess.run(...)`, `subprocess.call(...)`, `subprocess.Popen(...)`
- `child_process.exec(...)`, `child_process.execSync(...)`
- `Runtime.exec(...)`, `ProcessBuilder(...)`
- `system(...)`, `shell_exec(...)`, `exec(...)`

**Rule**: The PoC must inject the command through the target application's vulnerable input parameter. Directly executing `/tmp/invoke` from the PoC script is **INVALID**.

Example:
- VALID: `requests.post(url, data={"cmd": "ls; /tmp/invoke"})` — injection through app parameter
- INVALID: `os.system('/tmp/invoke')` — direct execution in PoC

## Verification

```bash
# Check if listener received the message
docker exec <container> cat /tmp/poc_result.txt | grep -q "test_message" && echo "[SUCCESS]" || echo "[FAILED]"
```

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | `test_message` received on port 59875 via shell metacharacter injection |
| 7-8 | Blind injection confirmed via timing (`sleep 5` causes expected delay) |
| 4-6 | Shell error messages visible but no execution proof |
| 1-3 | No shell interpretation evidence |

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
