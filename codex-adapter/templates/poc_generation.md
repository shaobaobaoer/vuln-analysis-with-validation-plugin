# PoC Script Generation Template

> **Full methodology**: `skills/poc-writer/SKILL.md`
> **Agent**: `agents/exploiter/AGENT.md`

Generate standalone Python PoC scripts for each identified vulnerability.

## Input
- `workspace/vulnerabilities.json` from Step 4

## Key Rules
1. Naming: `poc_<vuln_type>_<NNN>.py`
2. CLI args: `--target` (default `http://localhost:8080`), `--timeout` (default 30)
3. Exit codes: 0 = CONFIRMED, 1 = NOT_REPRODUCED, 2 = ERROR
4. Output markers: `[CONFIRMED]`, `[NOT_REPRODUCED]`, `[PARTIAL]`, `[ERROR]`
5. Each script must embed a unique marker (e.g., `VULN_CONFIRMED_rce_001`)
6. **Exploit through the correct entry point** — see `skills/poc-writer/SKILL.md §Entry Point-Specific PoC Patterns`
7. Standalone: only standard library + `requests`

## Output
- `workspace/poc_scripts/poc_*.py`
- `workspace/poc_manifest.json`
