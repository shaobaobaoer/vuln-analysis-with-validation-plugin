# Codex Prompt Pack: Reproduction And Validation

Use this file as the Codex prompt pack for `/reproduce`.

## Read Order

1. `../CODEX.md`
2. `../commands/reproduce.md`
3. `../agents/exploiter/AGENT.md`
4. `../templates/validation_framework.md`
5. `../skills/poc-writer/SKILL.md`
6. The validator skill that matches each finding type
7. `../roles/exploiter.md`

## Codex Execution Contract

- Perform the documented pre-flight checks before any PoC execution.
- Execute PoCs only against the Dockerized target.
- Re-initialize monitoring before retries.
- Use the matching `validate-*` skill for each finding type.
- Save canonical results to `workspace/results.json`.
- Never run PoC or validator Python directly on the host.
- For template-rendered `rce`, keep validation inside `../skills/validate-rce/SKILL.md` and load its `resources/template-engine-rce.md` guidance instead of using a standalone overlay skill.

## Expected Outputs

- `workspace/results.json`
- Updated PoC scripts if retries required fixes
