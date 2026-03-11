---
description: Run the full 8-step vulnerability analysis pipeline against a GitHub repository. Extracts target, builds Docker env, scans for vulns, generates PoCs, reproduces, and delivers report.
---

# /vuln-scan — Full Vulnerability Scan Pipeline

Run the complete vulnerability analysis pipeline against a GitHub repository.

## Usage

```
/vuln-scan <github_repo_url>
```

## Pipeline

Execute all 8 steps sequentially using the orchestrator agent:

1. **Target Extraction** → Clone repo, analyze project, write `workspace/target.json`
2. **Environment Setup** → Generate Dockerfile, build container, verify health
3. **Vulnerability Analysis** → Search CVEs + static analysis → `workspace/vulnerabilities.json`
4. **PoC Generation** → Write exploit scripts → `workspace/poc_scripts/`
5. **Reproduction** → Execute PoCs in Docker container
6. **Retry Loop** → Auto-fix failures, max 5 retries per vuln
7. **Validation** → Run type-specific validators from `skills/validate-*/SKILL.md`
8. **Report** → Generate `workspace/report/REPORT.md` + `summary.json`

## Instructions

1. Create `workspace/` directory if it doesn't exist
2. Delegate to the `orchestrator` agent defined in `agents/orchestrator.md`
3. The orchestrator will coordinate sub-agents (`analyzer`, `builder`, `exploiter`, `reporter`)
4. Use skills from `skills/` for type-specific logic
5. Use templates from `templates/` for prompt guidance at each step
6. Track state in `workspace/pipeline_state.json`

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
