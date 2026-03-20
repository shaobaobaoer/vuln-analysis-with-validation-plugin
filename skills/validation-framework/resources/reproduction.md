# Reproduction Verification Template

> **Full validation flow**: `skills/validation-framework/SKILL.md` (authoritative source)
> **Agent**: `agents/exploiter/AGENT.md`

Execute PoC scripts against the Docker-containerized target and verify results.

## Safety Rules
- ALL execution MUST happen against a running Docker container — NEVER on the host
- ALL Python MUST run inside Docker via `docker exec` — NEVER `python3` on host

## Input
- Running Docker container (verified via Step 3)
- PoC scripts from Step 5
- `skills/validation-framework/SKILL.md` for validation flow

## Execution Flow
1. **Pre-flight check**: Verify container running + app responds. Entry point verification per vulnerability.
2. **Environment init**: Deploy trigger binary, start TCP listeners, set up inotifywait (see `skills/validation-framework/SKILL.md §Step 1`)
3. **Execute PoCs**: `docker exec <container> python3 /app/poc_scripts/<script> --target http://localhost:<port>`
4. **Legitimacy check**: Scan PoC source for forbidden patterns (see `skills/validation-framework/SKILL.md §Step 3`)
5. **Type-specific verification**: Check success conditions (see `skills/validation-framework/SKILL.md §Step 4`)

## Outcomes
`[SUCCESS]` → CONFIRMED | `[FAILED]` → NOT_REPRODUCED | `[INVALID]` → rewrite PoC

## Output
`workspace/results.json`
