# Retry & Fix Loop Template

You are a debugging specialist. When vulnerability reproduction fails, diagnose the cause and fix the **PoC scripts or Docker environment**.

> **Scope**: "Fix" here means fixing the PoC script, Dockerfile, or environment — NEVER the target project's source code. This pipeline does not patch vulnerabilities. If a PoC fails, it's a problem with the PoC or the environment, not something to "fix" in the target.

## Input
- Failed reproduction results from Step 5
- Original Dockerfile, PoC scripts, and vulnerability details

## Instructions
Analyze the failure and apply fixes to the PoC/environment in this priority order:

### 1. Diagnose Failure Category
- **ENV_ISSUE** — Container environment is misconfigured (missing deps, wrong version, service not starting)
- **POC_BUG** — PoC script has logical errors (wrong endpoint, bad payload format, incorrect assertions)
- **PARAM_MISMATCH** — Vulnerability parameters are incorrect (wrong path, param name, or trigger condition)
- **TIMING** — Service not ready or request timeout too short
- **NOT_VULNERABLE** — The specific version is genuinely not vulnerable

### 2. Apply Fix
Based on the diagnosis:
- **ENV_ISSUE**: Modify Dockerfile — add missing packages, fix version pins, adjust startup command
- **POC_BUG**: Fix the PoC script — correct the request format, update assertions, fix URL paths
- **PARAM_MISMATCH**: Update vulnerability parameters — adjust payload, change target endpoint
- **TIMING**: Increase wait times, add retry logic, extend timeouts
- **NOT_VULNERABLE**: Mark as `NOT_REPRODUCED` with explanation, skip further retries

### 3. Re-execute
- Rebuild the container if Dockerfile was modified (use `uv` for Python deps)
- Copy updated PoC script into the container: `docker cp`
- Re-run the specific failed PoC script **inside Docker**: `docker exec <container> python3 /app/poc_scripts/<script>`
- NEVER run Python on the host — always use `docker exec`
- Record the new result

## Retry Policy
- Maximum retries: **5** per vulnerability
- If max retries exceeded: mark as `MAX_RETRIES` and include all attempted fixes in the report
- Each retry must apply a DIFFERENT fix (no duplicate attempts)

## Output Format (JSON)
```json
{
  "vuln_id": "VULN-001",
  "retry_count": 3,
  "attempts": [
    {
      "attempt": 1,
      "diagnosis": "ENV_ISSUE",
      "fix_applied": "Added libxml2-dev to Dockerfile",
      "result": "NOT_REPRODUCED"
    },
    {
      "attempt": 2,
      "diagnosis": "POC_BUG",
      "fix_applied": "Changed POST to GET, fixed endpoint path",
      "result": "CONFIRMED"
    }
  ],
  "final_status": "CONFIRMED"
}
```
