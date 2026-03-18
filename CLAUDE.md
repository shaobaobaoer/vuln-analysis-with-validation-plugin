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

9. **No manufactured vulnerabilities (Anti-Cheat — ABSOLUTE)**: The pipeline MUST ONLY find vulnerabilities that exist in the original target codebase. The following are STRICTLY FORBIDDEN:
   - Adding `exec()`, `eval()`, `pickle.loads()`, `subprocess.run(shell=True)`, or any other insecure patterns to the test harness, Dockerfile, or any wrapper code that do not exist in the original repository
   - Creating new HTTP endpoints, CLI subcommands, or library methods in the test harness that introduce insecure behavior not present in the original code
   - "Discovering" vulnerabilities in code the pipeline itself wrote
   - Any finding that traces back to builder-generated code (Dockerfile, test harness, wrapper scripts) rather than the original target source is INVALID and MUST be excluded
   - The test harness serves ONE purpose: expose the target application's existing functionality to the network/process boundary for testing. It MUST NOT add new functionality or insecure behavior.
   - **Self-check**: Before writing any `vulnerabilities.json` entry, the analyzer MUST verify: "Does this vulnerable code pattern exist in a file that was part of the original git clone?" If NO — exclude it.

## Critical Rules

### 1. Authorization
- NEVER run against systems without explicit written authorization
- All testing must be performed in isolated Docker containers
- This tool is for authorized pentesting, CTFs, and security research only

### 2. Code Style
- Python 3.12+ with type hints, PEP 8, minimal deps (standard library + `requests`)
- All Python scripts execute inside Docker — never on the host
- Use `uv` for all Python dependency management (never pip/conda directly)

### 3. PoC Script Convention
> See `skills/poc-writer/SKILL.md` for full naming rules, patterns, and anti-patterns.
- Naming: `poc_<vuln_type>_<NNN>.py` (3-digit zero-padded)
- CLI args: `--target` (default `http://localhost:8080`), `--timeout` (default 30)
- Exit codes: 0 = CONFIRMED, 1 = NOT_REPRODUCED, 2 = ERROR
- Output markers: `[CONFIRMED]`, `[NOT_REPRODUCED]`, `[PARTIAL]`, `[ERROR]`

### 4. Environment Setup Convention
> See `skills/environment-builder/SKILL.md` for full modular setup workflow.
- Auto-detect tech stack (Docker Compose > Dockerfile > manual setup)
- Use `uv` for Python deps; all Dockerfiles must include HEALTHCHECK
- Mandatory: write `ENVIRONMENT_SETUP.md` after every environment build

### 5. Docker Resource Labeling & Cleanup

All Docker resources MUST be labeled with `vuln-analysis.pipeline-id=<pipeline_id>` for safe, targeted cleanup. NEVER use `docker system prune`, `docker container prune`, or any broad cleanup command — only filter-based cleanup targeting this pipeline's label. See `agents/orchestrator/AGENT.md` §Docker Resource Cleanup for full labeling/cleanup procedures.

### 6. Report Format
- Markdown for human-readable reports
- JSON for machine-readable summaries
- Include: executive summary, per-vuln details, reproduction steps, remediation

### 7. Validation Framework
- All PoC validation uses the unified framework in `templates/validation_framework.md`
- Three outcomes: `[SUCCESS]`, `[FAILED]`, `[INVALID]`
- Anti-cheat legitimacy check: PoC must exploit through the target app, not call system APIs directly
- Shared infrastructure: trigger binary (`/tmp/invoke`), flag file (`/tmp/flag`), TCP listeners (ports 59875/59876), `inotifywait`

## Target Selection Guidelines

**Choose targets that have their own network attack surface.** A target is high-value if an attacker can reach it over the network without controlling any intermediate application code.

### High-Value Targets (genuine remote attack surface)

| Category | Examples |
|----------|---------|
| LLM/ML serving stacks | vLLM, text-generation-inference, LocalAI, Ollama, TorchServe, Triton |
| ML infrastructure | MLflow server, Kubeflow, Ray Serve, KServe, Seldon Core, BentoML server |
| Data pipeline orchestrators | Apache Airflow, Prefect, Dagster, Metaflow |
| Web applications | Any Flask/FastAPI/Django/Express app with real users |
| Distributed ML internals | Spark REST API (port 6066), Horovod rendezvous, PyTorch RPC |
| AI agent frameworks | Open WebUI, LibreChat, anything.llm, DB-GPT, PrivateGPT |
| Experiment trackers | MLflow, Weights & Biases on-prem, ClearML server |

### Low-Value Targets (pure libraries — no network attack surface)

For these targets, the pipeline can only find `dos` (algorithmic) or `command_injection` (shell=True in library). Scanning them for `rce` / `ssrf` / remote deser is methodologically invalid:

> pandas, numpy, scikit-learn, scipy, requests, urllib3, boto3, botocore, sqlalchemy, PyMySQL, psycopg2, PyTorch (training), TensorFlow (training), Keras, tokenizers, spaCy, NLTK, gensim, h5py, PyTables, matplotlib, seaborn, pillow, scikit-image, catboost, xgboost, chainer, transformers (inference-only), dill, cloudpickle

**If a low-value target is submitted**: Set `valid_vuln_types: ["dos", "command_injection"]`, note the limitation, and do NOT create HTTP wrappers. If no findings of these types exist, output `vulnerabilities: []` — this is a correct and honest result.

## Pipeline Steps

1. **Target Extraction** (mandatory) → `workspace/target.json` — includes `project_type`, `network_exploitable`, `valid_vuln_types`
2. **Environment Setup** (mandatory) → `workspace/Dockerfile`, `workspace/docker-compose.yml`
   - For `library` targets: Dockerfile installs library only, NO HTTP server
3. **Docker Readiness Gate** (mandatory) → Verify target app runs correctly inside Docker
   - For `library` targets: verify `import <library>` succeeds, not HTTP health check
4. **Vulnerability Analysis** (mandatory) → `workspace/vulnerabilities.json`
   - Gated by `valid_vuln_types` from Step 1
5. **PoC Generation** → `workspace/poc_scripts/`
   - For `library` targets: `import lib; lib.func(payload)` — never HTTP
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

rce, ssrf, insecure_deserialization, arbitrary_file_rw, dos, command_injection, sql_injection, xss

**Type scope by target type**:
- `webapp` / `service`: all 8 types
- `cli`: rce, arbitrary_file_rw, dos, command_injection
- `library`: dos, command_injection, insecure_deserialization (only if network-receiving)

## Entry Point Reachability (MANDATORY)

A vulnerability is only valid if an attacker can **reach** it through a public entry point. Every finding MUST include reachability assessment — findings with no reachable entry point are excluded.

### Entry Point Types by Target

| Target Type | Valid Entry Points | Invalid (Exclude) |
|-------------|-------------------|-------------------|
| **Library** | Public API: `import lib; lib.func()`, `lib.Class()`, `lib.Class.method()`, `lib.Class.static_method()` | Private functions (`_func`, `__func`), internal modules (`_internal/`), test files, dead code with no public caller |
| **Web App** | HTTP endpoints: routes, API endpoints, WebSocket handlers | Internal helpers not connected to any route, middleware internals with no user input path |
| **CLI Tool** | CLI commands and arguments reachable from the entry point binary | Internal functions not reachable from CLI argument parsing |

### Library Entry Point Rules (Language-Specific)

**Python**: Public = no leading underscore. `lib.func()`, `lib.Class()`, `obj.method()`, `Class.classmethod()`, `Class.staticmethod()`. Private = `_func`, `__func`, anything in `_internal/` or `_utils/` not re-exported in `__init__.py`.

**JavaScript/TypeScript**: Public = exported from package entry point (`main`/`exports` in `package.json`). Private = non-exported functions, internal modules.

**Go**: Public = capitalized identifiers (`lib.Function()`, `lib.Type{}`). Private = lowercase identifiers.

**Java**: Public = `public` access modifier. Private = `private`, `protected`, package-private.

### Reachability Assessment

For each vulnerability found, the analyzer MUST trace a call path from an entry point to the vulnerable code:

| Reachability | Meaning | Action |
|-------------|---------|--------|
| `reachable` | Clear path from public entry point → vulnerable code | **KEEP** — valid finding |
| `conditional` | Path exists but requires auth/admin/special config | **KEEP** — note the condition |
| `not_reachable` | No path from any public entry point | **EXCLUDE** — not exploitable |

### PoC Entry Point Rules

PoC scripts MUST exploit through the correct entry point:
- **Library**: PoC imports the library and calls public API functions (e.g., `import sample_lib; sample_lib.parse(malicious_input)`)
- **Web App**: PoC sends HTTP requests to exposed endpoints (e.g., `requests.post(f"{target}/api/exec", json=payload)`)
- **CLI Tool**: PoC invokes the CLI binary with crafted arguments (e.g., `subprocess.run(["tool", "--input", malicious_file])`)

## Code Security Review

Vulnerability analysis uses a mandatory 3-phase code audit: **Audit → Filter → Report**. Phase 2 filtering is MANDATORY — never output raw findings without filtering. See `skills/code-security-review/SKILL.md` for full methodology and `skills/code-security-review/resources/` for filtering rules.

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
│   └── validate-*/              #   8 type-specific validators (Steps 7-8)
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
