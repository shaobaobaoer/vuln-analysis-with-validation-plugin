# Vuln-Analysis — Automated Security Vulnerability Verification

This is a Claude plugin for automated security vulnerability verification of open-source libraries, web applications, and CLI tools. It is designed for authorized penetration testing, CTF competitions, and defensive security research.

## Project Overview

- **Purpose**: Automated vulnerability analysis pipeline — **discovery, reproduction, and reporting only**
- **Scope**: This pipeline does NOT fix or patch vulnerabilities. It identifies, reproduces, and reports them. Remediation advice in the report is recommendations only.
- **Language**: Python 3.12+
- **Dependencies**: `requests` (only external dependency)
- **Python package manager**: `uv` (NEVER use pip/conda/venv directly — always use `uv`)
- **Execution**: All testing and Python execution runs in isolated Docker containers

## Safety Invariants (NEVER violate)

> These rules are absolute. No step, agent, or retry logic may override them.

1. **Docker-only execution**: ALL PoC scripts, validators, and exploit code MUST execute against a Docker container. NEVER run any PoC script, exploit payload, or vulnerability test directly on the host machine. The only permitted target is `http://localhost:<port>` where the port is mapped from a running Docker container.

2. **Mandatory Steps 1-4**: Steps 1 (Target Extraction), 2 (Environment Setup), 3 (Docker Readiness Gate), and 4 (Vulnerability Analysis) are ALL mandatory. If any of these steps fail after retries, the pipeline MUST abort. There is no fallback, no skip, no "continue with user-provided data" for these steps.

3. **Docker readiness gate (Step 3)**: Before ANY vulnerability analysis or PoC execution (Step 4+), the Docker container MUST be verified to successfully run the target application. This means:
   - The container is running (`docker ps` shows it up)
   - The application inside responds correctly (HTTP 200 on the main endpoint, or CLI tool executes without error)
   - The health check passes
   - If the app does not work inside Docker, fix the Docker setup FIRST. Do NOT proceed to PoC generation/execution with a broken environment.

4. **No remediation step**: This pipeline does NOT automatically fix, patch, or modify the target project's source code. The scope is strictly: identify → reproduce → report. The "retry loop" fixes only PoC scripts and Docker environment, NEVER the target application. Remediation recommendations in the final report are advisory only.

5. **No host-side execution**: The following are FORBIDDEN on the host:
   - Running `python3 poc_*.py` directly on the host
   - Running ANY Python script that is part of the analysis/testing process on the host
   - Using `curl`/`wget` to exploit host-local services that are NOT Docker containers
   - Executing any command injection, file write, or deserialization payload outside Docker
   - The ONLY permitted host-side actions are: building Docker images, starting/stopping containers, and sending HTTP requests to Docker-exposed ports

6. **All Python execution inside Docker**: ANY Python code that needs to run during the analysis (PoC scripts, helper scripts, validators, JSON validators) MUST execute inside the Docker container. Use `docker exec` or `docker-compose exec` to run Python inside the container. NEVER invoke `python3` or `python` on the host for any pipeline step.

7. **Use `uv` for Python environment management**: All Dockerfiles and container environments MUST use [`uv`](https://github.com/astral-sh/uv) as the Python package manager. NEVER use `pip install`, `conda install`, or `python -m venv` in Dockerfiles or inside containers. Use `uv` for all dependency installation:
   - Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh` or `pip install uv` (bootstrap only)
   - Create venv: `uv venv`
   - Install deps: `uv pip install -r requirements.txt`
   - Run scripts: `uv run python script.py`
   - Sync project: `uv sync` (if pyproject.toml exists)

8. **Local-only Docker builds**: Docker images are built locally from base images for testing purposes ONLY. The following are FORBIDDEN:
   - `docker push` to any registry (docker.io, ghcr.io, ECR, ACR, etc.)
   - `docker tag` for the purpose of preparing a push
   - `docker login` to any registry
   - `docker save` / `docker export` for distribution
   - Any action that packages or uploads the built image outside the local machine
   - The pipeline ONLY builds images locally via `docker build` and runs them via `docker run` / `docker-compose up`. Built images are ephemeral testing artifacts, not distributable packages.

## Critical Rules

### 1. Authorization
- NEVER run against systems without explicit written authorization
- All testing must be performed in isolated Docker containers
- This tool is for authorized pentesting, CTFs, and security research only

### 2. Code Style
- Python 3.12+ with type hints
- Follow PEP 8 conventions
- Minimal dependencies (standard library + `requests` only)
- Each PoC script must be independently runnable
- All scripts must include timeout control (default: 30s)
- All Python scripts execute inside Docker — never on the host
- Use `uv` for all Python dependency management (never pip/conda directly)

### 3. PoC Script Convention
- Naming: `poc_<vuln_type>_<id>.py`
- CLI args: `--target` (default `http://localhost:8080`), `--timeout` (default 30)
- Exit codes: 0 = CONFIRMED, 1 = NOT_REPRODUCED, 2 = ERROR
- Output: `[CONFIRMED]`, `[NOT_REPRODUCED]`, `[PARTIAL]`, `[ERROR]` with vuln ID
- Must use unique markers to avoid false positives

### 4. Environment Setup Convention
- Auto-detect tech stack before building (Docker Compose > Dockerfile > manual setup)
- **Python package management: always use `uv`** (never pip/conda/venv directly)
- Database provisioning via Docker containers (PostgreSQL, MySQL, Redis, MongoDB)
- All Dockerfiles must include HEALTHCHECK
- All Dockerfiles for Python projects must install `uv` and use it for dependency management
- Use `setup_` prefix for auto-created environments; never delete user environments
- Mandatory: write `ENVIRONMENT_SETUP.md` after every environment build

### 5. Docker Resource Labeling & Cleanup

All Docker resources (containers, images, networks, volumes) created by the pipeline MUST be labeled with the pipeline ID for safe, targeted cleanup.

**Label convention**:
- Label key: `vuln-analysis.pipeline-id`
- Label value: the pipeline's `pipeline_id` (e.g., `vuln-a1b2c3d4`)

**Applying labels**:
```dockerfile
# In Dockerfile
LABEL vuln-analysis.pipeline-id="vuln-a1b2c3d4"
```
```bash
# In docker run
docker run --label "vuln-analysis.pipeline-id=vuln-a1b2c3d4" ...
```
```yaml
# In docker-compose.yml
services:
  app:
    labels:
      vuln-analysis.pipeline-id: "vuln-a1b2c3d4"
```

**Safe cleanup** (only removes resources belonging to THIS pipeline run):
```bash
PIPELINE_ID="vuln-a1b2c3d4"

# 1. Stop and remove containers
docker ps -aq --filter "label=vuln-analysis.pipeline-id=${PIPELINE_ID}" | xargs -r docker rm -f

# 2. Remove images
docker images -q --filter "label=vuln-analysis.pipeline-id=${PIPELINE_ID}" | xargs -r docker rmi -f

# 3. Remove networks
docker network ls -q --filter "label=vuln-analysis.pipeline-id=${PIPELINE_ID}" | xargs -r docker network rm

# 4. Remove volumes
docker volume ls -q --filter "label=vuln-analysis.pipeline-id=${PIPELINE_ID}" | xargs -r docker volume rm
```

**FORBIDDEN cleanup commands** (too aggressive, will destroy other running containers):
```bash
docker system prune              # Kills ALL unused resources across the system
docker container prune           # Kills ALL stopped containers, not just ours
docker image prune -a            # Kills ALL unused images
docker rm -f $(docker ps -aq)    # Kills ALL containers
docker-compose down -v --rmi all # Removes images that may be shared
```

**When to clean up**:
- After Step 9 (report) completes successfully
- On pipeline abort (Steps 1-4 failure)
- On `--restart` before beginning a new run
- NEVER during active PoC execution (Steps 7-8)

### 6. Report Format
- Markdown for human-readable reports
- JSON for machine-readable summaries
- Include: executive summary, per-vuln details, reproduction steps, remediation

### 7. Validation Framework
- All PoC validation uses the unified framework in `templates/validation_framework.md`
- Three outcomes: `[SUCCESS]`, `[FAILED]`, `[INVALID]`
- Anti-cheat legitimacy check: PoC must exploit through the target app, not call system APIs directly
- Shared infrastructure: trigger binary (`/tmp/invoke`), flag file (`/tmp/flag`), TCP listeners (ports 59875/59876), `inotifywait`

## Pipeline Steps

1. **Target Extraction** (mandatory) → `workspace/target.json`
2. **Environment Setup** (mandatory) → `workspace/Dockerfile`, `workspace/docker-compose.yml`
3. **Docker Readiness Gate** (mandatory) → Verify target app runs correctly inside Docker
4. **Vulnerability Analysis** (mandatory) → `workspace/vulnerabilities.json`
5. **PoC Generation** → `workspace/poc_scripts/`
6. **Environment Init** → Deploy trigger binary, start listeners, set up monitors
7. **Reproduction + Validation** → Execute PoCs + legitimacy check + type-specific validation → `workspace/results.json`
8. **Retry Loop** → Max 5 retries per vulnerability (re-initialize monitors each retry)
9. **Report** → `workspace/report/REPORT.md`

**Abort conditions**: Steps 1-4 failing = pipeline abort. No fallback, no skip.

## Available Commands

- `/vuln-scan` — Full 9-step pipeline against a GitHub repository
- `/env-setup` — Docker environment setup only
- `/poc-gen` — PoC script generation only
- `/reproduce` — Reproduction and validation only
- `/report` — Report generation only

## Vulnerability Types Covered

rce, ssrf, insecure_deserialization, arbitrary_file_rw, dos, command_injection

## Code Security Review

The `skills/code-security-review/` skill implements a mandatory 3-phase code audit process (integrated from `anthropics/claude-code-security-review`):

1. **Phase 1 — Audit**: Context research, comparative analysis, vulnerability assessment
2. **Phase 2 — Filter**: Hard exclusion regex pass → AI filtering (19 rules) → Precedent check (17 rules) → Confidence scoring (1-10, threshold >= 7)
3. **Phase 3 — Report**: Filter table, detailed findings, excluded summary

Resources in `skills/code-security-review/resources/`:
- `audit-prompt.md` — Audit methodology and severity guidelines
- `filtering-rules.md` — 19 hard exclusions, 17 precedents, confidence scale
- `hard-exclusion-patterns.md` — Regex-based auto-exclusion patterns
- `customization-guide.md` — Extension system for custom rules

**Critical**: Phase 2 filtering is MANDATORY. Never output raw findings without filtering.

## File Structure

```
vuln-analysis/
├── CLAUDE.md                    # This file
├── README.md
├── requirements.txt
├── .gitignore
├── commands/                    # Slash commands (5 commands)
│   ├── vuln-scan.md             #   /vuln-scan — full 9-step pipeline
│   ├── env-setup.md             #   /env-setup — environment setup only
│   ├── poc-gen.md               #   /poc-gen — PoC generation only
│   ├── reproduce.md             #   /reproduce — reproduction + retry
│   └── report.md                #   /report — report generation only
├── skills/                      # Skill modules (11 skills)
│   ├── target-extraction/       #   Step 1: target analysis
│   ├── environment-builder/     #   Step 2: modular env setup (app/ db/ helpers/ scripts/)
│   ├── vulnerability-scanner/   #   Step 4: vuln discovery with integrated filtering
│   ├── code-security-review/    #   3-phase code audit (with resources/)
│   ├── poc-writer/              #   Step 5: PoC script patterns
│   └── validate-*/              #   6 type-specific validators (Steps 7-8)
├── agents/                      # Agent definitions (5 agents)
│   ├── orchestrator/AGENT.md    #   Pipeline coordinator (opus)
│   ├── analyzer/AGENT.md        #   Target + vuln analysis (opus)
│   ├── builder/AGENT.md         #   Environment setup (sonnet)
│   ├── exploiter/AGENT.md       #   PoC execution + retry (opus)
│   └── reporter/AGENT.md        #   Report generation (sonnet)
├── templates/                   # Prompt templates (8 files)
├── core/                        # Python framework
│   ├── pipeline.py              #   Pipeline orchestrator
│   ├── runner.py                #   PoC script runner
│   ├── validators/              #   Base + 6 concrete validators
│   ├── reporters/               #   Markdown + JSON reporters
│   └── runners/                 #   Docker manager
└── examples/
    ├── dockerfiles/             #   Example Docker configs
    └── poc_scripts/             #   6 example PoC scripts
```
