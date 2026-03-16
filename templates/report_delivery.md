# Report Delivery Template

You are a security report writer. Compile all findings into a comprehensive vulnerability report.

## Input
- All results from Steps 1-7
- Validation statuses for each vulnerability

## Report Structure

### 1. Executive Summary
- Target name, version, repository
- Total vulnerabilities found / confirmed / not reproduced
- Overall risk assessment (CRITICAL / HIGH / MEDIUM / LOW)

### 2. Reproduction Environment (one-time setup)

Provide the **complete, copy-paste-ready** commands to recreate the Docker environment from scratch:

```markdown
#### Prerequisites
- Docker 20.10+ installed
- Source code cloned: `git clone <repo_url> && cd <repo_name>`

#### Build & Start
\```bash
# Build the image
docker build -t vuln-<pipeline_id>-target .

# Start the container
docker run -d --name vuln-<pipeline_id>-app -p <host_port>:<container_port> vuln-<pipeline_id>-target

# Wait for service to become healthy
until curl -sf http://localhost:<host_port>/ > /dev/null 2>&1; do sleep 2; done
echo "Service is ready"
\```

#### Dockerfile Used
\```dockerfile
<full Dockerfile contents>
\```
```

### 3. Vulnerability Details (per vulnerability)

For each **CONFIRMED** vulnerability, include a **self-contained reproduction block** that a reader can follow independently:

- **ID**: VULN-XXX
- **Type**: Category name
- **CVE**: CVE ID or N/A
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Status**: CONFIRMED
- **Description**: What the vulnerability is
- **Affected Component**: File path + line number, endpoint, or parameter
- **Entry Point Type**: `library_api` / `webapp_endpoint` / `cli_command`
- **Entry Point Path**: The public API call, HTTP endpoint, or CLI command through which this vulnerability is reachable (e.g., `sample_lib.parse()`, `POST /api/exec`, `tool --input`)
- **Access Level**: public / authenticated / admin
- **Call Chain**: Trace from public entry point → intermediate functions → vulnerable code (e.g., `POST /api/exec → handle_exec() → eval(user_input)`)

#### Reproduction (per vulnerability)

Each confirmed vulnerability MUST include a complete reproduction block with these 5 parts:

1. **Pre-conditions** — What monitoring/infrastructure to set up before running the PoC:
   ```bash
   # Example: For RCE — start TCP listener inside container
   docker exec -d vuln-app sh -c 'timeout 60 nc -l -p 59875 > /tmp/poc_result.txt 2>&1 &'
   ```

2. **PoC Execution** — The exact command to run the PoC script:
   ```bash
   # Copy PoC into container and execute
   docker cp poc_scripts/poc_rce_001.py vuln-app:/app/
   docker exec vuln-app python3 /app/poc_rce_001.py --target http://localhost:<internal_port> --timeout 30
   ```

3. **Expected Output** — What the PoC prints on success:
   ```
   [CONFIRMED] VULN-001: RCE via eval() in /api/exec — marker VULN_CONFIRMED_rce_001 found
   Exit code: 0
   ```

4. **Verification** — How to independently verify the exploit worked:
   ```bash
   # For RCE: check if trigger binary sent message to listener
   docker exec vuln-app cat /tmp/poc_result.txt | grep "test_message"
   ```

5. **Payload** — The actual exploit payload used (sanitized if needed):
   ```python
   payload = "__import__('os').system('/tmp/invoke')"
   requests.post(f"{target}/api/exec", json={"code": payload})
   ```

#### Evidence
- Request/response snippets or validation output showing successful exploitation

#### Remediation
- Recommended fix (advisory only — this pipeline does not auto-fix)

### 4. Not Reproduced Findings
- List each NOT_REPRODUCED / PARTIAL / MAX_RETRIES vulnerability
- Explain **why** reproduction failed (environment issue, code not reachable, etc.)
- Include the retry history and diagnoses attempted

### 5. PoC Scripts Reference
- Table of all PoC scripts: Script Name | Vuln ID | Type | Description | CLI Args
- General execution pattern: `docker exec <container> python3 /app/<script> --target http://localhost:<port> --timeout 30`

### 6. Appendix
- Full reproduction logs
- Retry attempt history per vulnerability
- Validation framework output (SUCCESS/FAILED/INVALID per vuln)
- Raw output data

## Output Files
1. `report/REPORT.md` — Full Markdown report
2. `report/summary.json` — Machine-readable summary
3. `report/evidence/` — Evidence files (logs, screenshots)
