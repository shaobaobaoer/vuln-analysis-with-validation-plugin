---
description: Execute PoC scripts against the containerized target environment and verify vulnerability reproduction. Includes automatic retry loop for failures.
---

# /reproduce — Run Vulnerability Reproduction

Execute PoC scripts against the target and verify reproduction.

## Usage

```
/reproduce [--poc <script>] [--retry <max_retries>]
```

## Instructions

1. Verify container is running (start if needed)
2. Delegate to the `exploiter` agent (`agents/exploiter.md`)
3. Execute each PoC from `workspace/poc_manifest.json`
4. For failures, enter retry loop (max 5 per vuln):
   - Diagnose: ENV_ISSUE / POC_BUG / PARAM_MISMATCH / TIMING / NOT_VULNERABLE
   - Apply fix and re-execute
5. Run type-specific validators from `skills/validate-*/SKILL.md`
6. Save results to `workspace/results.json`
7. Cleanup containers after completion

## Output

- `workspace/results.json`
- Updated PoC scripts (if fixed during retries)
