# Codex Prompt Pack: PoC Generation

Use this file as the Codex equivalent of the original Claude `/poc-gen` command.

## Read Order

1. `../CLAUDE.md`
2. `../commands/poc-gen.md`
3. `../agents/exploiter/AGENT.md`
4. `../skills/poc-writer/SKILL.md`
5. `../roles/exploiter.md`

## Codex Execution Contract

- Read `workspace/vulnerabilities.json`.
- Generate one standalone PoC per vulnerability under `workspace/poc_scripts/`.
- Preserve the naming convention `poc_<type>_<NNN>.py`.
- Every script must support `--target` and `--timeout`.
- Validate syntax inside Docker, not on the host.
- For template-rendered `rce`, keep the flow inside `../skills/poc-writer/SKILL.md` and load its `resources/template-engine-rce.md` guidance instead of using a standalone overlay skill.

## Expected Outputs

- `workspace/poc_scripts/poc_<type>_<NNN>.py`
- `workspace/poc_manifest.json`
