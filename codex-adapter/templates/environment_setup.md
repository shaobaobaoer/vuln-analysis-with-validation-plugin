# Environment Setup Template

> **Full methodology**: `skills/environment-builder/SKILL.md` (with sub-modules in `app/`, `db/`, `helpers/`)
> **Agent**: `agents/builder/AGENT.md`

Build an isolated Docker environment for vulnerability testing.

## Input
- `workspace/target.json` from Step 1
- Source code of the target project

## Pipeline
Detect Source → Network Check → Identify Stack → Route Sub-Modules → Build → Verify → Document

## Key Rules
1. **Priority**: Docker Compose > Dockerfile > manual setup
2. **Python**: Always use `uv` for dependency management (never pip/conda directly)
3. **Label all resources**: `vuln-analysis.pipeline-id=<pipeline_id>`
4. **HEALTHCHECK** required in all Dockerfiles
5. **Documentation**: Write `ENVIRONMENT_SETUP.md` after every build (mandatory)

## Output
- `workspace/Dockerfile`, `workspace/docker-compose.yml`
- Running, healthy Docker container
- `ENVIRONMENT_SETUP.md`
