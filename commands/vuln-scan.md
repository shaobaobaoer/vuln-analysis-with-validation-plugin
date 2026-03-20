---
description: Run the full 9-step vulnerability analysis pipeline against a GitHub repository. Extracts target, builds Docker env, scans for vulns, generates PoCs, reproduces with anti-cheat validation, and delivers report.
---

# /vuln-scan — Full Vulnerability Scan Pipeline

Run the complete **9-step** vulnerability analysis pipeline against a GitHub repository.

> **Scope**: This pipeline **identifies, reproduces, and reports** vulnerabilities. It does NOT fix or patch them.

## Usage

```
/vuln-scan <github_repo_url>
```

## Activation Map

> Each step loads ONLY the listed skills. Nothing else activates.

| Step | Agent | Skills Loaded | Condition |
|------|-------|---------------|-----------|
| 1 — Target Extraction | `analyzer` | `target-extraction` | always |
| 2 — Environment Setup | `builder` | `environment-builder` | always |
| 3 — Docker Readiness Gate | orchestrator direct | — | always |
| 4 — Vulnerability Analysis | `analyzer` | `vulnerability-scanner`, `code-security-review` | always; resources load by detected language/framework |
| 5 — PoC Generation | `exploiter` | `poc-writer` | always |
| 6 — Environment Init | orchestrator direct | — | always |
| 7 — Reproduction | `exploiter` | `validate-{type}` per finding | **only** validators matching types in `vulnerabilities.json` |
| 8 — Retry Loop | `exploiter` | same as Step 7 + `poc-writer` for rewrites | only for failed findings |
| 9 — Report | `reporter` | — | always |

**Type routing**: Step 4 output is gated by `skills/type-mapping.md` (language x target_type → valid_vuln_types). Step 7 loads only the validators for types that passed Step 4.

## Safety Rules

> See `agents/orchestrator/AGENT.md §Safety Invariants` for the full 9 rules.

- **Docker-only**: All execution inside Docker. If Docker is unavailable, pipeline MUST abort.
- **Steps 1-4 are mandatory**: Pipeline aborts if any fails.
- **Sub-agent delegation**: The orchestrator delegates to sub-agents — never performs specialized work itself.

## Pipeline

1. **Target Extraction** (mandatory) → `workspace/target.json` (must include `entry_points[]`, `language`, `project_type`, `valid_vuln_types`)
2. **Environment Setup** (mandatory) → `workspace/Dockerfile`, `workspace/docker-compose.yml`
3. **Docker Readiness Gate** (mandatory) → Verify target app runs in Docker
4. **Vulnerability Analysis** (mandatory) → `workspace/vulnerabilities.json` (only types allowed by `valid_vuln_types` from Step 1)
5. **PoC Generation** → `workspace/poc_scripts/`
6. **Environment Init** → Deploy trigger binary, start TCP listeners, set up file monitors
7. **Reproduction + Validation** → `workspace/results.json`
8. **Retry Loop** → Max 5 retries per vuln
9. **Report** → `workspace/report/REPORT.md` + `summary.json`

**Abort conditions**: Steps 1-4 failing = pipeline abort. Docker unavailable = immediate abort.

## Instructions

1. Create `workspace/` directory if it doesn't exist
2. Delegate to `agents/orchestrator/AGENT.md` — it coordinates all work through sub-agents
3. The orchestrator delegates to: `analyzer` (Steps 1, 4), `builder` (Step 2), `exploiter` (Steps 5-8), `reporter` (Step 9)
4. Track state in `workspace/pipeline_state.json` with exactly 9 step entries

## Output

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
