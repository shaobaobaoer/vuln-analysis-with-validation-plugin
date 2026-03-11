---
description: Run the full 8-step vulnerability analysis pipeline against a GitHub repository. Extracts target, builds Docker env, scans for vulns, generates PoCs, reproduces, and delivers report.
---

# /vuln-scan — Full Vulnerability Scan Pipeline

Run the complete vulnerability analysis pipeline against a GitHub repository.

## Usage

```
/vuln-scan <github_repo_url>
```

## Safety Rules

- **Docker-only**: All PoC execution happens inside Docker containers. NEVER run exploits on the host.
- **Steps 1-3 are mandatory**: If any of Target Extraction, Environment Setup, or Vulnerability Analysis fails, the pipeline aborts.
- **Docker readiness gate**: The target app must be verified working inside Docker before any PoC execution begins.

## Pipeline

Execute all steps sequentially using the orchestrator agent:

1. **Target Extraction** (mandatory) → Clone repo, analyze project → `workspace/target.json`
2. **Environment Setup** (mandatory) → Generate Dockerfile, build container, verify health
3. **Docker Readiness Gate** (mandatory) → Verify the target app runs correctly inside Docker (HTTP 200 / CLI works)
4. **Vulnerability Analysis** (mandatory) → Search CVEs + static analysis → `workspace/vulnerabilities.json`
5. **PoC Generation** → Write exploit scripts targeting Docker container → `workspace/poc_scripts/`
6. **Reproduction** → Execute PoCs against Docker container (NEVER on host)
7. **Retry Loop** → Auto-fix failures, max 5 retries per vuln
8. **Validation** → Run type-specific validators from `skills/validate-*/SKILL.md`
9. **Report** → Generate `workspace/report/REPORT.md` + `summary.json`

**Abort conditions**: Steps 1-4 failing = pipeline abort. No fallback, no skip.

## Instructions

1. Create `workspace/` directory if it doesn't exist
2. Delegate to the `orchestrator` agent defined in `agents/orchestrator.md`
3. The orchestrator will coordinate sub-agents (`analyzer`, `builder`, `exploiter`, `reporter`)
4. The orchestrator MUST verify Docker readiness before delegating to the exploiter
5. Use skills from `skills/` for type-specific logic
6. Use templates from `templates/` for prompt guidance at each step
7. Track state in `workspace/pipeline_state.json`

## Output

All artifacts in `workspace/`:
```
workspace/
├── target.json
├── vulnerabilities.json
├── Dockerfile
├── docker-compose.yml
├── poc_manifest.json
├── results.json
├── pipeline_state.json
├── poc_scripts/
└── report/
    ├── REPORT.md
    └── summary.json
```
