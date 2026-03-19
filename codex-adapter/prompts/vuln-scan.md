# Codex Prompt Pack: Full Vulnerability Scan

Use this file as the Codex prompt pack for `/vuln-scan`.

## Read Order

1. `../CODEX.md`
2. `../commands/vuln-scan.md`
3. `../agents/orchestrator/AGENT.md`
4. `../skills/target-extraction/SKILL.md`
5. `../skills/environment-builder/SKILL.md`
6. `../skills/vulnerability-scanner/SKILL.md`
7. `../skills/code-security-review/SKILL.md`
8. `../skills/poc-writer/SKILL.md`
9. The specific `../skills/validate-*/SKILL.md` files needed for each finding type
10. `../roles/orchestrator.md`

## Codex Execution Contract

- Follow the full 9-step pipeline exactly as documented.
- Treat Steps 1-4 as mandatory abort gates.
- Use `spawn_agent` to mirror the original role split:
  - analyzer: Steps 1 and 4
  - builder: Step 2
  - exploiter: Steps 5, 7, and 8
  - reporter: Step 9
- Keep `workspace/pipeline_state.json` aligned with the documented 9-step state shape.
- Abort immediately if Docker is unavailable; do not fall back to host execution.
- Keep original plugin files read-only. Write runtime artifacts only to `workspace/` unless the user asks for something else.
- When template rendering, SSTI, or sandbox escape is in scope, use the parent `rce` skills and let them load their embedded `resources/template-engine-rce.md` guidance. Do not treat template-engine `rce` as a standalone skill or type.

## Expected Outputs

- `workspace/target.json`
- `workspace/vulnerabilities.json`
- `workspace/Dockerfile`
- `workspace/docker-compose.yml`
- `workspace/poc_manifest.json`
- `workspace/results.json`
- `workspace/pipeline_state.json`
- `workspace/poc_scripts/`
- `workspace/report/REPORT.md`
- `workspace/report/summary.json`
