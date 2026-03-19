# Codex Prompt Pack: PoC Generation

Use this file as the Codex equivalent of the original Claude `/poc-gen` command.

## Read Order

1. `../CLAUDE.md`
2. `../commands/poc-gen.md`
3. `../agents/exploiter/AGENT.md`
4. `../skills/poc-writer/SKILL.md`
5. `../skills/template-engine-rce/SKILL.md` when an `rce` finding is sourced from template rendering or sandbox escape
6. `../roles/exploiter.md`

## Codex Execution Contract

- Read `workspace/vulnerabilities.json`.
- Generate one standalone PoC per vulnerability under `workspace/poc_scripts/`.
- Preserve the naming convention `poc_<type>_<NNN>.py`.
- Every script must support `--target` and `--timeout`.
- Validate syntax inside Docker, not on the host.

## Expected Outputs

- `workspace/poc_scripts/poc_<type>_<NNN>.py`
- `workspace/poc_manifest.json`
