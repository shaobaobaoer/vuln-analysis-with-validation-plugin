---
description: Execute PoC scripts against the containerized target environment and verify vulnerability reproduction. Includes automatic retry loop for failures.
---

# /reproduce — Run Vulnerability Reproduction

Execute PoC scripts against the Docker-containerized target and verify reproduction.

## Safety Rules

- **Docker-only**: ALL PoC execution MUST happen against a running Docker container. NEVER run exploits on the host.
- **Pre-flight check**: Docker container MUST be running AND the target app MUST respond before any PoC execution.

## Usage

```
/reproduce [--poc <script>] [--retry <max_retries>]
```

## Instructions

1. **Pre-flight check** (mandatory, before anything else):
   - Verify Docker container is running (`docker ps`)
   - Verify the target app responds correctly inside Docker (HTTP 200 or CLI executes)
   - If container is down, start it: `docker-compose up -d`
   - If app doesn't respond after container start, **abort** — do NOT proceed with broken environment
2. Delegate to the `exploiter` agent (`agents/exploiter.md`)
3. Execute each PoC from `workspace/poc_manifest.json` against `http://localhost:<docker_port>`
4. For failures, enter retry loop (max 5 per vuln):
   - Diagnose: ENV_ISSUE / POC_BUG / PARAM_MISMATCH / TIMING / NOT_VULNERABLE
   - Apply fix and re-execute
5. Run type-specific validators from `skills/validate-*/SKILL.md`
6. Save results to `workspace/results.json`
7. Cleanup containers after completion

## Output

- `workspace/results.json`
- Updated PoC scripts (if fixed during retries)
