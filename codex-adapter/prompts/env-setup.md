# Codex Prompt Pack: Environment Setup

Use this file as the Codex prompt pack for `/env-setup`.

## Read Order

1. `../CODEX.md`
2. `../commands/env-setup.md`
3. `../agents/analyzer/AGENT.md`
4. `../agents/builder/AGENT.md`
5. `../skills/target-extraction/SKILL.md`
6. `../skills/environment-builder/SKILL.md`
7. `../roles/analyzer.md`
8. `../roles/builder.md`

## Codex Execution Contract

- First run target extraction and write `workspace/target.json`.
- Then build the Docker environment through the builder role.
- Verify the container is healthy before reporting success.
- If Docker is unavailable, fail instead of falling back to host execution.
- Write the environment documentation file required by the original workflow.

## Expected Outputs

- `workspace/target.json`
- `workspace/Dockerfile`
- `workspace/docker-compose.yml`
- `workspace/build.log`
- `workspace/ENVIRONMENT_SETUP.md`
- A running healthy container
