---
description: Execute PoC scripts against the containerized target environment and verify vulnerability reproduction. Includes automatic retry loop for failures.
---

# /reproduce — Run Vulnerability Reproduction

Execute PoC scripts against the Docker-containerized target and verify reproduction.

## Usage

```
/reproduce [--poc <script>] [--retry <max_retries>]
```

## Activation Map

| Step | Agent | Skills Loaded | Condition |
|------|-------|---------------|-----------|
| 6 — Environment Init | orchestrator direct | — | always |
| 7 — Reproduction | `exploiter` | `validate-{type}` per finding | **only** validators matching finding types |
| 8 — Retry Loop | `exploiter` | same as Step 7 + `poc-writer` for rewrites | only for failed findings |

**Validator routing**: See `skills/type-mapping/SKILL.md §Validator Routing` — each finding type maps to exactly one validator skill.

## Safety Rules

- **Docker-only**: ALL PoC execution via `docker exec`. NEVER run exploits on the host.
- **Pre-flight**: Docker container MUST be running AND target app MUST respond before any execution.

## Instructions

1. **Pre-flight check**: Verify container running, app responding
2. **Initialize monitoring**: Deploy trigger binary, TCP listeners, file monitors per `skills/validation-framework/SKILL.md`
3. Delegate to `agents/exploiter/AGENT.md`
4. Execute each PoC from `workspace/poc_manifest.json`
5. **Legitimacy check**: Anti-cheat scan of PoC source
6. **Type-specific validation**: Load `validate-{type}` skill for each finding
7. Retry loop (max 5 per vuln): re-init monitors, diagnose, fix, re-execute
8. Save results to `workspace/results.json`
9. Cleanup Docker resources using label-based cleanup (NEVER `docker system prune`)

## Output

- `workspace/results.json`
- Updated PoC scripts (if fixed during retries)
