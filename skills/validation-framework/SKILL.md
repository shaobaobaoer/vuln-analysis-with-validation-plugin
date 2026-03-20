---
name: validation-framework
description: Unified PoC validation framework defining observable, automatable, cheat-proof success criteria for all vulnerability types. Provides shared infrastructure (trigger binary, TCP listeners, file monitors) and the canonical 6-step validation flow.
origin: vuln-analysis
---

# Unified PoC Validation Framework

This framework defines **observable, automatable, cheat-proof** success criteria for PoC validation. The core principle: a PoC must exploit through the actual vulnerability entry point — never by directly calling system APIs, reading files, or connecting to listeners from the PoC script itself.

## Design Principles

1. **Observable results** — Success is bound to: file access events, port messages, file creation, response content, or response time.
2. **Real exploitation only** — The PoC must trigger the vulnerability through the target application's own vulnerable code path. Direct system calls from the PoC script are **INVALID**.
3. **Automation-friendly** — All checks use `/tmp/poc_result.txt`, TCP listeners, `inotifywait`, and regex scanning for fully automated batch validation.
4. **Three possible outcomes**: `[SUCCESS]`, `[FAILED]`, `[INVALID]`

> **Note**: PoC scripts print their own stdout markers (`[CONFIRMED]`, `[NOT_REPRODUCED]`, `[PARTIAL]`, `[ERROR]` — see `skills/poc-writer/SKILL.md`). These are **input** to this validation framework. The framework then evaluates legitimacy and produces one of the three outcomes above.

## Shared Infrastructure

### Trigger Binary (`/tmp/invoke`)

A pre-compiled Go binary that sends `test_message` to `localhost:59875` via TCP. Used to verify RCE, command injection, and code injection.

**Source** (Go):
```go
package main
import ("fmt"; "net"; "os")
func main() {
    conn, err := net.Dial("tcp", "localhost:59875")
    if err != nil { fmt.Fprintf(os.Stderr, "connection failed: %v\n", err); os.Exit(1) }
    defer conn.Close()
    conn.Write([]byte("test_message\n"))
}
```

The compiled binary is at `skills/validation-framework/resources/trigger.linux`. Deploy to Docker as `/tmp/invoke`:
```bash
docker cp skills/validation-framework/resources/trigger.linux <container>:/tmp/invoke
docker exec <container> chmod +x /tmp/invoke
```

### Flag File (`/tmp/flag`)

A known file used to verify arbitrary file read/write:
```bash
docker exec <container> sh -c 'echo "FLAG_CONTENT_$(date +%s)" > /tmp/flag'
```

### TCP Listener (Port 59875 — RCE/Command Injection)

```bash
docker exec -d <container> sh -c '
  timeout 60 sh -c "nc -l -p 59875 > /tmp/poc_result.txt 2>&1" &
'
```

### TCP Listener (Port 59876 — SSRF)

```bash
docker exec -d <container> sh -c '
  timeout 60 sh -c "nc -l -p 59876 > /tmp/ssrf_result.txt 2>&1" &
'
```

### File Monitor (inotifywait — Arbitrary File R/W)

```bash
docker exec -d <container> sh -c '
  apt-get install -y inotify-tools 2>/dev/null || apk add inotify-tools 2>/dev/null
  timeout 60 inotifywait -m /tmp/flag -e access,modify,open,close_write \
    --format "%T %e %f" --timefmt "%H:%M:%S" > /tmp/poc_result.txt 2>&1 &
'
```

---

## Unified Validation Flow (6 Steps)

### Step 0: Entry Point Verification (MANDATORY)

Before executing any PoC, verify the target entry point actually exists and responds:

**Web App endpoints**:
```bash
# Verify the endpoint exists (use the entry_point.path from vulnerabilities.json)
curl -sf -o /dev/null -w "%{http_code}" http://localhost:<port>/api/exec
# Accept: 200, 401, 403, 405 (endpoint exists). Reject: 000, 404 (endpoint missing)
```

**Library API**:
```bash
# Verify the library is importable and the function exists
docker exec <container> python3 -c "import sample_lib; assert hasattr(sample_lib, 'parse')"
```

**CLI commands**:
```bash
# Verify the CLI tool runs and accepts the relevant argument
docker exec <container> tool --help | grep -q "input"
```

**If entry point does NOT exist**: Mark the vulnerability as `[FAILED]` with reason `ENTRY_POINT_NOT_FOUND`. Do NOT execute the PoC — it would produce a false result. This typically indicates a false positive from the analysis phase.

### Step 1: Environment Initialization

Before any PoC execution, set up all monitoring infrastructure inside the Docker container:

```bash
# 1a. Create flag file
docker exec <container> sh -c 'echo "FLAG_CONTENT_$(date +%s)" > /tmp/flag'

# 1b. Deploy trigger binary
docker cp skills/validation-framework/resources/trigger.linux <container>:/tmp/invoke
docker exec <container> chmod +x /tmp/invoke

# 1c. Clean up marker files
docker exec <container> rm -f /tmp/deserialized_flag /tmp/poc_result.txt /tmp/ssrf_result.txt

# 1d. Start TCP listener (port 59875 for RCE/cmd injection)
docker exec -d <container> sh -c 'timeout 60 nc -l -p 59875 > /tmp/poc_result.txt 2>&1 &'

# 1e. Start TCP listener (port 59876 for SSRF)
docker exec -d <container> sh -c 'timeout 60 nc -l -p 59876 > /tmp/ssrf_result.txt 2>&1 &'

# 1f. Start file monitor (for arbitrary file R/W)
docker exec -d <container> sh -c '
  inotifywait -m /tmp/flag -e access,modify,open,close_write \
    --format "%T %e %f" --timefmt "%H:%M:%S" > /tmp/inotify_result.txt 2>&1 &
'
```

### Step 2: Execute PoC

Send the attack payload through the target application's vulnerable entry point. The PoC MUST interact with the application's API/endpoint/parameter — never directly with the OS.

### Step 3: Legitimacy Check (Anti-Cheat)

Scan the PoC script source code for forbidden patterns. If any match, the result is `[INVALID]`:

**Forbidden patterns by vulnerability type:**

| Vuln Type | Forbidden in PoC Code |
|-----------|----------------------|
| RCE | `child_process.exec`, `Runtime.exec`, `ProcessBuilder`, `os.system`, `subprocess`, `shell_exec` — used directly (not as payload string) |
| Command Injection | Same as RCE — the injection must happen via the target app's parameter |
| Arbitrary File R/W | `open('/tmp/flag')`, `cat /tmp/flag`, direct file read in PoC code (not via the target app) |
| SSRF | `requests.get('http://127.0.0.1:59876')` or any direct connection to 59876 from the PoC |
| Insecure Deser | `touch /tmp/deserialized_flag` or direct file creation in PoC code |
| DoS | Concurrent flood requests, manually stopping the service |
| SQL Injection | Direct database connections (`psycopg2.connect()`, `pymysql.connect()`, `sqlite3.connect()`) — injection MUST go through the target app's HTTP interface |
| XSS | Browser automation (`selenium`, `playwright`) — reflection check MUST use HTTP response body analysis only |

**Rule**: The forbidden patterns apply to the PoC's own logic, NOT to payload strings embedded in the attack. For example, `payload = "__import__('os').system('/tmp/invoke')"` is valid (it's a string sent to the target), but `os.system('/tmp/invoke')` called directly in the PoC is INVALID.

### Step 4: Type-Specific Success Check

| Vuln Type | Success Condition | How to Check |
|-----------|------------------|--------------|
| Arbitrary File Read | `inotifywait` detects `ACCESS`/`OPEN` on `/tmp/flag` | `docker exec <container> cat /tmp/inotify_result.txt \| grep -i "access\|open"` |
| Arbitrary File Write | `inotifywait` detects `MODIFY`/`CLOSE_WRITE` on `/tmp/flag` | `docker exec <container> cat /tmp/inotify_result.txt \| grep -i "modify\|close_write"` |
| RCE | Listener on 59875 receives `test_message` | `docker exec <container> cat /tmp/poc_result.txt \| grep "test_message"` |
| Command Injection | Listener on 59875 receives `test_message` | Same as RCE |
| SSRF | Listener on 59876 receives any connection | `docker exec <container> cat /tmp/ssrf_result.txt \| grep -c .` (non-empty) |
| Insecure Deser | `/tmp/deserialized_flag` file exists | `docker exec <container> test -f /tmp/deserialized_flag && echo EXISTS` |
| DoS | Response time >= 10x baseline | Compare `attack_time / baseline_time >= 10` |
| SQL Injection | SQL error in HTTP response OR time >= 4× baseline OR boolean diff >= 50 bytes | `docker exec <container> curl -sf "http://localhost:<port>/endpoint?id=%27" \| grep -iE "sql syntax\|ORA-\|syntax error"` |
| XSS | Unique marker present unescaped in HTTP response body | `docker exec <container> curl -sf "http://localhost:<port>/endpoint?q=<payload>" \| grep "<MARKER>"` |
| IDOR | HTTP 200 with target user's data returned via different user's credentials | `docker exec <container> curl -sf -H "Authorization: Bearer ${TOKEN1}" "http://localhost:<port>/api/users/${USER2_ID}" \| grep "${USER2_USERNAME}"` |

### Step 5: Output Result

| Result | Meaning |
|--------|---------|
| `[SUCCESS]` | Success condition met AND legitimacy check passed |
| `[FAILED]` | Success condition not met (vulnerability not triggered) |
| `[INVALID]` | PoC uses forbidden patterns — cheating detected |

After determining the result, write the PoC's entry in `results.json` using the **canonical schema** (see `skills/poc-writer/SKILL.md §results.json Schema`):

```json
{
  "vuln_id": "VULN-001",
  "poc_script": "poc_rce_001.py",
  "vuln_type": "rce",
  "status": "SUCCESS",
  "exit_code": 0,
  "retries": 0,
  "validation_result": {
    "marker": "CONFIRMED",
    "evidence": "<one sentence describing the proof>"
  }
}
```

**Mandatory rules**:
- `validation_result.marker` MUST be present and MUST be one of: `"CONFIRMED"`, `"NOT_REPRODUCED"`, `"PARTIAL"`, `"ERROR"` (string, no brackets)
- Do NOT use `confirmed`, `outcome`, `poc_output`, `result`, or any other field name for the confirmation status
- `summary.confirmed` MUST be an integer count of entries where `marker == "CONFIRMED"`

---

## Per-Type Detail

### Arbitrary File Read/Write

**Target**: `/tmp/flag`

- **Read**: The PoC sends a path traversal or file inclusion payload to make the target application read `/tmp/flag`. Success = `inotifywait` detects `ACCESS`/`OPEN`.
- **Write**: The PoC sends a payload to make the target application write to `/tmp/flag`. Success = `inotifywait` detects `MODIFY`/`CLOSE_WRITE`.

**Invalid patterns**:
- PoC directly opens/reads `/tmp/flag`
- PoC directly executes `cat /tmp/flag`
- PoC passes `/tmp/flag` as a direct business parameter without exploiting a vulnerability

### RCE (Remote Code Execution)

**Target**: Execute `/tmp/invoke` → sends `test_message` to port 59875.

**Payloads**: The PoC injects code (via eval, template injection, etc.) that executes `/tmp/invoke` on the server side.

**Invalid patterns**:
- PoC directly calls `os.system('/tmp/invoke')` in its own code
- PoC uses `subprocess.run()`, `child_process.exec()`, etc. directly
- Must go through the target app's vulnerable code path

### Command Injection

**Target**: Execute `/tmp/invoke` via shell metacharacter injection.

**Example payloads**: `; /tmp/invoke`, `| /tmp/invoke`, `&& /tmp/invoke`, `` `/tmp/invoke` ``

**Invalid patterns**: Same as RCE — the injection must be through the target app's parameter, not direct execution in the PoC script.

### SSRF

**Target**: Make the server connect to `127.0.0.1:59876`.

**Example payloads**: `http://127.0.0.1:59876`, `http://localhost:59876`, `http://0x7f000001:59876`, `http://[::1]:59876`

**Invalid patterns**:
- PoC script itself connecting to 59876
- Must be the target server making the outbound request

### Insecure Deserialization

**Target**: Create `/tmp/deserialized_flag` via deserialization.

**Supported formats**: Python pickle, YAML, PHP unserialize, Java ObjectInputStream.

**Example** (Python pickle):
```python
payload = pickle.dumps(EvilClass())  # EvilClass.__reduce__ returns os.system('touch /tmp/deserialized_flag')
```

**Invalid patterns**:
- PoC directly touches/creates `/tmp/deserialized_flag`
- Must be created by the deserialization execution chain

### DoS (Denial of Service)

**Target**: Single malicious request causes >= 10x response time increase.

**Covered scenarios**: ReDoS, nested JSON, XML bomb, large payloads.

**Validation**:
1. Measure baseline: average of 3 normal requests
2. Send attack payload
3. Calculate ratio: `attack_time / baseline_avg`
4. Success if ratio >= 10 or service becomes unresponsive

**Invalid patterns**:
- Concurrent flood / high-volume traffic
- Manually stopping the service
- Must demonstrate single-request vulnerability
