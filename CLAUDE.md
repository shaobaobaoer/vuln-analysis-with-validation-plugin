# Vuln-Analysis — Automated Security Vulnerability Verification

This is a Claude plugin for automated security vulnerability verification of open-source libraries, web applications, and CLI tools. It is designed for authorized penetration testing, CTF competitions, and defensive security research.

## Project Overview

- **Purpose**: Automated 8-step vulnerability analysis pipeline
- **Language**: Python 3.12+
- **Dependencies**: `requests` (only external dependency)
- **Execution**: All testing runs in isolated Docker containers

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

### 3. PoC Script Convention
- Naming: `poc_<vuln_type>_<id>.py`
- CLI args: `--target` (default `http://localhost:8080`), `--timeout` (default 30)
- Exit codes: 0 = CONFIRMED, 1 = NOT_REPRODUCED, 2 = ERROR
- Output: `[CONFIRMED]`, `[NOT_REPRODUCED]`, `[PARTIAL]`, `[ERROR]` with vuln ID
- Must use unique markers to avoid false positives

### 4. Environment Setup Convention
- Auto-detect tech stack before building (Docker Compose > Dockerfile > manual setup)
- Supports conda, venv, Docker Compose, and direct Dockerfile
- Database provisioning via Docker containers (PostgreSQL, MySQL, Redis, MongoDB)
- All Dockerfiles must include HEALTHCHECK
- Use `setup_` prefix for auto-created environments; never delete user environments
- Mandatory: write `ENVIRONMENT_SETUP.md` after every environment build
- Cleanup containers after testing

### 5. Report Format
- Markdown for human-readable reports
- JSON for machine-readable summaries
- Include: executive summary, per-vuln details, reproduction steps, remediation

## Pipeline Steps

1. **Target Extraction** → `workspace/target.json`
2. **Environment Setup** → `workspace/Dockerfile`
3. **Vulnerability Analysis** → `workspace/vulnerabilities.json`
4. **PoC Generation** → `workspace/poc_scripts/`
5. **Reproduction** → `workspace/results.json`
6. **Retry Loop** → Max 5 retries per vulnerability
7. **Validation** → Type-specific validators
8. **Report** → `workspace/report/REPORT.md`

## Available Commands

- `/vuln-scan` — Full 8-step pipeline against a GitHub repository
- `/env-setup` — Docker environment setup only
- `/poc-gen` — PoC script generation only
- `/reproduce` — Reproduction and validation only
- `/report` — Report generation only

## Vulnerability Types Covered

path_traversal, rce, lfi, ssrf, insecure_deserialization, idor, arbitrary_file_rw, dos, xss, command_injection

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
│   ├── vuln-scan.md             #   /vuln-scan — full 8-step pipeline
│   ├── env-setup.md             #   /env-setup — environment setup only
│   ├── poc-gen.md               #   /poc-gen — PoC generation only
│   ├── reproduce.md             #   /reproduce — reproduction + retry
│   └── report.md                #   /report — report generation only
├── skills/                      # Skill modules (15 skills)
│   ├── target-extraction/       #   Step 1: target analysis
│   ├── environment-builder/     #   Step 2: modular env setup (app/ db/ helpers/ scripts/)
│   ├── vulnerability-scanner/   #   Step 3: vuln discovery with integrated filtering
│   ├── code-security-review/    #   3-phase code audit (with resources/)
│   ├── poc-writer/              #   Step 4: PoC script patterns
│   └── validate-*/              #   10 type-specific validators
├── agents/                      # Agent definitions (5 agents)
│   ├── orchestrator.md          #   Pipeline coordinator (opus)
│   ├── analyzer.md              #   Target + vuln analysis (opus)
│   ├── builder.md               #   Environment setup (sonnet)
│   ├── exploiter.md             #   PoC execution + retry (opus)
│   └── reporter.md              #   Report generation (sonnet)
├── templates/                   # Prompt templates (7 pipeline steps)
├── core/                        # Python framework
│   ├── pipeline.py              #   Pipeline orchestrator
│   ├── runner.py                #   PoC script runner
│   ├── validators/              #   Base + 10 concrete validators
│   ├── reporters/               #   Markdown + JSON reporters
│   └── runners/                 #   Docker manager
└── examples/
    ├── dockerfiles/             #   Example Docker configs
    └── poc_scripts/             #   10 example PoC scripts
```
