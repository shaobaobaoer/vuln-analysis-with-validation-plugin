---
description: Run the full 9-step vulnerability analysis pipeline against a GitHub repository. Extracts target, builds Docker env, scans for vulns, generates PoCs, reproduces with anti-cheat validation, and delivers report.
---

# /vuln-scan — Full Vulnerability Scan Pipeline

Run the complete **9-step** vulnerability analysis pipeline against a GitHub repository.

> **Scope**: This pipeline **identifies, reproduces, and reports** vulnerabilities. It does NOT fix or patch them. Remediation advice in the report is recommendations only.

## Usage

```
/vuln-scan <github_repo_url>
```

## Safety Rules

> See `CODEX.md §Safety Invariants` for the full 9 rules.

- **Docker-only**: All execution inside Docker. If Docker is unavailable, pipeline MUST abort.
- **Steps 1-4 are mandatory**: Pipeline aborts if any fails.
- **Sub-agent delegation**: The orchestrator MUST delegate to sub-agents (analyzer, builder, exploiter, reporter) — never perform specialized work itself.

## Pipeline (EXACTLY 9 steps — not 8, not 7)

Execute all 9 steps sequentially using the orchestrator agent:

1. **Target Extraction** (mandatory) → Clone repo, analyze project, **enumerate all public entry points** → `workspace/target.json` (must include `entry_points[]`)
2. **Environment Setup** (mandatory) → Generate Dockerfile, build container, verify health. **If Docker is not accessible, ABORT the pipeline.**
3. **Docker Readiness Gate** (mandatory) → Verify the target app runs correctly inside Docker (HTTP 200 / CLI works)
4. **Vulnerability Analysis** (mandatory) → Search CVEs + static analysis + **entry point reachability assessment** → `workspace/vulnerabilities.json` (only reachable/conditional findings with confidence >= 7, types limited to the 12 supported types; language-gated: jndi_injection→Java, prototype_pollution→JS/TS, pickle_deserialization→Python)
5. **PoC Generation** → Write exploit scripts targeting Docker container → `workspace/poc_scripts/`
6. **Environment Init** → Deploy trigger binary, start TCP listeners, set up file monitors (see `templates/validation_framework.md`)
7. **Reproduction + Validation** → Execute PoCs **inside Docker via `docker exec`** → legitimacy check (anti-cheat) → type-specific validation → `workspace/results.json`
8. **Retry Loop** → Auto-fix failures, re-initialize monitors, max 5 retries per vuln
9. **Report** → Generate `workspace/report/REPORT.md` + `summary.json`

**Abort conditions**: Steps 1-4 failing = pipeline abort. No fallback, no skip. Docker unavailable = immediate abort.

## Instructions

1. Create `workspace/` directory if it doesn't exist
2. **Delegate to the `orchestrator` agent** defined in `agents/orchestrator/AGENT.md` — the orchestrator coordinates all work through sub-agents
3. **The orchestrator MUST NOT perform specialized work directly** — it delegates to: `analyzer` (Steps 1, 4), `builder` (Step 2), `exploiter` (Steps 5, 7, 8), `reporter` (Step 9)
4. The orchestrator MUST verify Docker readiness (Step 3) before delegating to the exploiter
5. Use skills from `skills/` for type-specific logic
6. Use templates from `templates/` for prompt guidance at each step
7. Track state in `workspace/pipeline_state.json` with **exactly 9 step entries**

### Orchestrator Invocation

When invoking the orchestrator agent, the prompt MUST:
- Reference the **9-step pipeline** (NEVER say "8-step" or any other number)
- List all 9 steps by their correct names
- Include the target repository URL
- Remind the orchestrator to delegate to sub-agents
- Remind the orchestrator that Docker is mandatory (abort if unavailable)

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
