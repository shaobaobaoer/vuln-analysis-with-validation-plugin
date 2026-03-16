---
description: Execute PoC scripts against the containerized target environment and verify vulnerability reproduction. Includes automatic retry loop for failures.
---

# /reproduce — Run Vulnerability Reproduction

Execute PoC scripts against the Docker-containerized target and verify reproduction.

## Safety Rules

- **Docker-only**: ALL PoC execution MUST happen against a running Docker container. NEVER run exploits on the host.
- **All Python inside Docker**: ALL Python scripts (PoC, validators) MUST execute inside the container via `docker exec`. NEVER run `python3` on the host.
- **Use `uv`**: Python dependencies in the container are managed with `uv` (never pip directly).
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
   - **Entry point verification**: For each vulnerability, verify the declared entry point exists before running its PoC (HTTP endpoint returns non-404, library function is importable, CLI command accepts the argument)
2. **Initialize monitoring** — Deploy trigger binary, start TCP listeners, set up file monitors per `templates/validation_framework.md`
3. Delegate to the `exploiter` agent (`agents/exploiter/AGENT.md`)
4. Execute each PoC from `workspace/poc_manifest.json` against `http://localhost:<docker_port>`
5. **Legitimacy check** — Scan PoC source for forbidden direct-call patterns (anti-cheat)
6. **Type-specific validation** — Check success condition per vulnerability type
7. For failures, enter retry loop (max 5 per vuln):
   - Re-initialize monitoring (restart listeners, clean markers)
   - Diagnose: ENTRY_POINT_NOT_FOUND / ENV_ISSUE / POC_BUG / PARAM_MISMATCH / TIMING / NOT_VULNERABLE
   - Apply fix and re-execute
8. Save results to `workspace/results.json` (outcomes: `[SUCCESS]`, `[FAILED]`, `[INVALID]`)
9. Cleanup containers after completion

## Output

- `workspace/results.json`
- Updated PoC scripts (if fixed during retries)
