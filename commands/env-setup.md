---
description: Generate and build a Docker environment for a target project without running the full vulnerability scan. Outputs Dockerfile and verifies container health.
---

# /env-setup — Environment Setup Only

Generate and build a Docker environment for a target project.

## Usage

```
/env-setup <github_repo_url>
```

## Instructions

1. Run target extraction (Step 1) to identify project type → `workspace/target.json`
2. Delegate to the `builder` agent (`agents/builder.md`)
3. Use `skills/environment-builder/SKILL.md` for Dockerfile generation patterns
4. Build, start, and verify the container is healthy
5. On build failure, diagnose and fix (max 3 attempts)

## Output

- `workspace/Dockerfile`
- `workspace/docker-compose.yml` (if multi-service)
- `workspace/target.json`
- Console output confirming successful build and startup
