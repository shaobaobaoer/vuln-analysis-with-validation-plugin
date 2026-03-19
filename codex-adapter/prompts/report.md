# Codex Prompt Pack: Report Generation

Use this file as the Codex equivalent of the original Claude `/report` command.

## Read Order

1. `../CLAUDE.md`
2. `../commands/report.md`
3. `../agents/reporter/AGENT.md`
4. `../templates/report_delivery.md`
5. `../skills/template-engine-rce/SKILL.md` when reporting template-rendered `rce` or sandbox-escape findings
6. `../roles/reporter.md`

## Codex Execution Contract

- Read the completed workspace artifacts directly.
- Generate `workspace/report/REPORT.md` and `workspace/report/summary.json`.
- Ensure the report is self-contained and derived from actual PoC scripts, not only manifest metadata.
- When a finding contains template-engine `rce` metadata, include the engine, control mode, sandbox status, and payload family in the report text.
- Verify both report files exist before marking the task complete.

## Expected Outputs

- `workspace/report/REPORT.md`
- `workspace/report/summary.json`
- Copied report artifacts under `workspace/report/`
