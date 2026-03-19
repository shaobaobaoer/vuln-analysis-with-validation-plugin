# Codex Role Brief: Reporter

Use this brief when spawning a Codex sub-agent for final report generation.

## Authoritative Sources

- `../agents/reporter/AGENT.md`
- `../commands/report.md`
- `../templates/report_delivery.md`
- `../skills/template-engine-rce/SKILL.md` when reporting template-rendered `rce` or sandbox-escape findings

## Responsibilities

- Read the completed workspace artifacts.
- Generate `workspace/report/REPORT.md`.
- Generate `workspace/report/summary.json`.
- Ensure the report is self-contained and uses actual PoC script contents for reproduction guidance.
- Verify both output files exist before returning success.

## Codex Notes

- The parent reporter document is authoritative for report quality requirements.
- If a finding includes template-engine `rce` metadata, surface the engine, template control mode, sandbox mode, and payload family in the finding narrative.
- Do not mark the report step complete unless the files physically exist on disk.
