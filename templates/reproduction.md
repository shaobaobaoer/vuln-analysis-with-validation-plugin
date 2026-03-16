# Reproduction Verification Template

You are a QA security engineer. Execute PoC scripts against the Docker-containerized target and verify results using the unified validation framework.

## Safety Rules

> **ABSOLUTE**: All PoC execution MUST happen against a running Docker container. NEVER execute any exploit on the host machine. If Docker is not running or the app doesn't work inside Docker, STOP immediately.
>
> **ALL PYTHON INSIDE DOCKER**: ALL Python scripts (PoC scripts, validators, helpers) MUST execute inside the Docker container via `docker exec`. NEVER run `python3` or `python` directly on the host machine. Use `uv` for dependency management inside the container.

## Input
- Built Docker environment from Step 2, verified working via Step 3 (Docker Readiness Gate)
- PoC scripts from Step 5
- Validation framework: `templates/validation_framework.md`

## Instructions

### Step 1: Pre-Flight Check (MANDATORY)
1. Verify Docker container is running: `docker ps | grep <container_name>`
2. Verify the target app responds correctly inside Docker:
   - Web apps: `curl -sf http://localhost:<port>/` returns HTTP 200
   - CLI tools: `docker exec <container> <tool> --version` succeeds
3. If the container is down → start it: `docker-compose up -d`
4. If the app does not respond after startup → **ABORT reproduction. Fix Docker setup first.**

### Step 2: Environment Initialization

Set up all monitoring infrastructure before executing any PoC:

```bash
# Create flag file (for arbitrary file R/W)
docker exec <container> sh -c 'echo "FLAG_CONTENT_$(date +%s)" > /tmp/flag'

# Deploy trigger binary (for RCE/command injection)
docker cp trigger.linux <container>:/tmp/invoke
docker exec <container> chmod +x /tmp/invoke

# Clean up previous markers
docker exec <container> rm -f /tmp/deserialized_flag /tmp/poc_result.txt /tmp/ssrf_result.txt /tmp/inotify_result.txt

# Start TCP listener on port 59875 (RCE/command injection)
docker exec -d <container> sh -c 'timeout 60 nc -l -p 59875 > /tmp/poc_result.txt 2>&1 &'

# Start TCP listener on port 59876 (SSRF)
docker exec -d <container> sh -c 'timeout 60 nc -l -p 59876 > /tmp/ssrf_result.txt 2>&1 &'

# Start file monitor (for arbitrary file R/W — install inotify-tools if needed)
docker exec <container> sh -c 'apt-get install -y inotify-tools 2>/dev/null || apk add inotify-tools 2>/dev/null'
docker exec -d <container> sh -c 'timeout 60 inotifywait -m /tmp/flag -e access,modify,open,close_write --format "%T %e %f" --timefmt "%H:%M:%S" > /tmp/inotify_result.txt 2>&1 &'
```

**Note**: Only set up infrastructure relevant to the vulnerability types being tested.

### Step 3: PoC Execution (Docker-only)

```bash
# Copy PoC scripts into the container
docker cp poc_scripts/ <container_name>:/app/poc_scripts/

# Install PoC dependencies inside container using uv
docker exec <container_name> uv pip install --system requests

# Execute PoCs INSIDE the Docker container (NEVER on host)
for poc in poc_scripts/*.py; do
  pocname=$(basename "$poc")
  docker exec <container_name> python3 /app/poc_scripts/"$pocname" --target http://localhost:<internal_port>
done
```

**CRITICAL**: NEVER run `python3 poc_*.py` directly on the host. ALL Python execution uses `docker exec`.

### Step 4: Legitimacy Check (Anti-Cheat)

Scan each PoC script's source code for forbidden patterns:

| Vuln Type | Forbidden Direct Calls in PoC Code |
|-----------|-----------------------------------|
| RCE / Command Injection | `os.system(...)`, `subprocess.run(...)` — called directly (not as payload string) |
| Arbitrary File R/W | `open('/tmp/flag')`, `cat /tmp/flag` — direct file access |
| SSRF | `requests.get('http://127.0.0.1:59876')` — PoC directly connects |
| Insecure Deserialization | `touch /tmp/deserialized_flag` — direct file creation |
| DoS | Threading/multiprocessing for concurrent flooding |

If any match: result is `[INVALID]`. The PoC must be rewritten to exploit through the target app's vulnerable code path.

### Step 5: Type-Specific Verification

| Vuln Type | Success Condition | Check Command |
|-----------|------------------|---------------|
| RCE | `test_message` received on port 59875 | `docker exec <container> grep "test_message" /tmp/poc_result.txt` |
| Command Injection | `test_message` received on port 59875 | Same as RCE |
| SSRF | Any connection received on port 59876 | `docker exec <container> cat /tmp/ssrf_result.txt \| grep -c .` |
| Insecure Deserialization | `/tmp/deserialized_flag` exists | `docker exec <container> test -f /tmp/deserialized_flag` |
| Arbitrary File Read | `inotifywait` detects ACCESS/OPEN | `docker exec <container> grep -i "access\|open" /tmp/inotify_result.txt` |
| Arbitrary File Write | `inotifywait` detects MODIFY/CLOSE_WRITE | `docker exec <container> grep -i "modify\|close_write" /tmp/inotify_result.txt` |
| DoS | Response time >= 10x baseline | Compare `attack_time / baseline_avg >= 10` |

### Three Possible Outcomes

| Result | Meaning |
|--------|---------|
| `[SUCCESS]` | Success condition met AND legitimacy check passed → maps to `CONFIRMED` |
| `[FAILED]` | Success condition not met → maps to `NOT_REPRODUCED` |
| `[INVALID]` | PoC uses forbidden patterns → rewrite PoC and re-execute |

## Output Format (JSON)
```json
{
  "target": "<project_name>",
  "environment": "<docker_image_tag>",
  "execution_time": "<total_seconds>",
  "results": [
    {
      "vuln_id": "VULN-001",
      "poc_script": "poc_rce_001.py",
      "status": "CONFIRMED|NOT_REPRODUCED|PARTIAL|ERROR|INVALID",
      "validation_result": "[SUCCESS]|[FAILED]|[INVALID]",
      "exit_code": 0,
      "duration_seconds": 2.5,
      "output": "<captured_stdout>",
      "error": "<captured_stderr_if_any>",
      "legitimacy_check": "PASSED|FAILED",
      "evidence": {
        "marker_found": true,
        "marker_type": "tcp_message|file_event|marker_file|response_time",
        "marker_detail": "test_message received on port 59875"
      }
    }
  ],
  "summary": {
    "total": 5,
    "confirmed": 3,
    "not_reproduced": 1,
    "partial": 0,
    "invalid": 1,
    "error": 0
  }
}
```
