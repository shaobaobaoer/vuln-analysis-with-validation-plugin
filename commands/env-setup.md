---
description: Generate and build a Docker environment for a target project without running the full vulnerability scan. Outputs Dockerfile and verifies container health.
---

# /env-setup — Environment Setup Only

Generate and build a Docker environment for a target project.

## Usage

```
/env-setup <github_repo_url>
```

## Activation Map

| Step | Agent | Skills Loaded | Condition |
|------|-------|---------------|-----------|
| 1 — Target Extraction | `analyzer` | `target-extraction` | always |
| 2 — Environment Setup | `builder` | `environment-builder` | always |
| 3 — Docker Readiness Gate | orchestrator direct | — | always |

## Instructions

1. Run target extraction → `workspace/target.json`
2. Delegate to `agents/builder/AGENT.md`
3. Builder uses `skills/environment-builder/SKILL.md` (routes to language-specific sub-modules by `target.json.language`)
4. Build, start, and verify the container is healthy
5. On build failure, diagnose and fix (max 3 attempts)

## Output

- `workspace/target.json`
- `workspace/Dockerfile`
- `workspace/docker-compose.yml`
- `workspace/build.log`
- `workspace/ENVIRONMENT_SETUP.md`
- Running, healthy Docker container
