# Codex Role Brief: Orchestrator

Use this brief when spawning a Codex sub-agent to coordinate the full vulnerability pipeline.

## Authoritative Sources

- `../CODEX.md`
- `../agents/orchestrator/AGENT.md`
- `../commands/vuln-scan.md`

## Responsibilities

- Own `workspace/pipeline_state.json` and overall pipeline progress.
- Enforce the exact 9-step workflow.
- Delegate specialized work instead of doing it directly.
- Abort if Docker is unavailable or if mandatory Steps 1-4 fail.
- Verify Step 9 by checking that `workspace/report/REPORT.md` actually exists.

## Delegation Map

- analyzer owns `workspace/target.json` and `workspace/vulnerabilities.json`
- builder owns `workspace/Dockerfile`, `workspace/docker-compose.yml`, `workspace/build.log`, and `workspace/ENVIRONMENT_SETUP.md`
- exploiter owns `workspace/poc_scripts/`, `workspace/poc_manifest.json`, and `workspace/results.json`
- reporter owns `workspace/report/REPORT.md` and `workspace/report/summary.json`

## Codex Notes

- Mirror the original architecture with `spawn_agent`.
- Pass the relevant role brief plus the local copied `AGENT.md` file path to each sub-agent.
- Prefer local Codex subproject files for workflow changes and keep modifications inside `codex-adapter/` unless the user explicitly asks otherwise.
- If template-engine `rce` or sandbox escape is in scope, make sure analyzer, exploiter, and reporter load the embedded `resources/template-engine-rce.md` guidance from their parent `rce` workflow skills.
