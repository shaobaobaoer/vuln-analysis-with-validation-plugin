# Codex Role Brief: Builder

Use this brief when spawning a Codex sub-agent for Docker environment setup.

## Authoritative Sources

- `../agents/builder/AGENT.md`
- `../skills/environment-builder/SKILL.md`

## Responsibilities

- Detect the target stack and choose the right environment-builder branch.
- Produce `workspace/Dockerfile` and `workspace/docker-compose.yml` when needed.
- Build and start the target in Docker.
- Verify health and write `workspace/ENVIRONMENT_SETUP.md`.
- Keep every Docker resource labeled with the pipeline id.

## Codex Notes

- Use `uv` for Python dependency management inside Docker.
- Never fall back to host-side venv, pip, or local execution.
- Do not manufacture new attack surface in any helper wrapper.
