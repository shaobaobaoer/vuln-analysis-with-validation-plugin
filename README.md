# Vuln-Analysis: Automated Security Vulnerability Verification Plugin

A Claude Code / Codex plugin for automated security vulnerability verification of open-source libraries, web applications, and CLI tools.

> **Authorization Notice**: This tool is designed for authorized security testing, penetration testing engagements, CTF competitions, and defensive security research only.

## Overview

This plugin automates the full vulnerability analysis lifecycle through a **9-step pipeline**:

1. **Target Extraction** — Clone repo, analyze project type, enumerate all public entry points
2. **Environment Setup** — Auto-detect stack, build Docker container, verify health
3. **Docker Readiness Gate** — Verify target app runs correctly inside Docker before proceeding
4. **Vulnerability Analysis** — Scan for CVEs + static analysis with entry point reachability assessment
5. **PoC Generation** — Write exploit scripts targeting the Docker container via correct entry points
6. **Environment Init** — Deploy trigger binary, start TCP listeners, set up file monitors
7. **Reproduction + Validation** — Execute PoCs, legitimacy check (anti-cheat), type-specific validation
8. **Retry Loop** — Auto-fix failures, re-initialize monitors (up to 5 retries per vulnerability)
9. **Report** — Generate comprehensive Markdown report with copy-paste-ready reproduction steps

**Abort conditions**: Steps 1-4 are mandatory. If any fails, the pipeline aborts.

## Directory Structure

```
vuln-analysis-with-validation-plugin/
├── .claude-plugin/
│   ├── plugin.json                        # Plugin metadata (required)
│   └── marketplace.json                   # Marketplace listing
├── commands/                              # Slash commands
│   ├── vuln-scan.md                       #   /vuln-scan — full 9-step pipeline
│   ├── env-setup.md                       #   /env-setup — Docker env only
│   ├── poc-gen.md                         #   /poc-gen — generate PoCs
│   ├── reproduce.md                       #   /reproduce — run reproduction
│   └── report.md                          #   /report — generate report
├── agents/                                # Agent definitions
│   ├── orchestrator/AGENT.md              #   Pipeline coordinator (opus)
│   ├── analyzer/AGENT.md                  #   Target + vuln analysis (opus)
│   ├── builder/AGENT.md                   #   Docker env builder (sonnet)
│   ├── exploiter/AGENT.md                 #   PoC execution + retry (opus)
│   └── reporter/AGENT.md                  #   Report generation (sonnet)
├── skills/                                # Skill modules
│   ├── target-extraction/SKILL.md         #   Step 1: target + entry point analysis
│   ├── environment-builder/               #   Step 2: modular env setup
│   │   ├── SKILL.md
│   │   ├── app/                           #     Language-specific setup
│   │   ├── db/                            #     Database provisioning
│   │   ├── helpers/                       #     Network/image/port checks
│   │   ├── output/                        #     ENVIRONMENT_SETUP.md template
│   │   └── scripts/                       #     Shell automation
│   ├── vulnerability-scanner/SKILL.md     #   Step 4: vuln discovery with filtering
│   ├── code-security-review/              #   3-phase code audit
│   │   ├── SKILL.md
│   │   └── resources/
│   ├── poc-writer/SKILL.md                #   Step 5: PoC script patterns
│   ├── validate-*/SKILL.md               #   12 type-specific validators
│   └── _shared/                           #   Cross-skill shared resources
│       ├── validation_framework.md        #     Unified PoC validation framework
│       ├── reproduction.md                #     Reproduction verification
│       └── trigger.linux                  #     Trigger binary for validation
├── core/                                  # Python framework
│   ├── pipeline.py                        #   Pipeline orchestrator
│   ├── runner.py                          #   PoC script runner
│   ├── validators/                        #   Base + concrete validators
│   ├── reporters/                         #   Markdown + JSON report generators
│   └── runners/                           #   Docker manager
├── tools/                                 # Workspace validation tools
├── examples/                              # Example PoCs and Dockerfiles
├── README.md                              # This file
├── requirements.txt
├── install-claude.sh                      # Install for Claude Code (--local for project-level)
└── install-codex.sh                       # Install for Codex (--local for project-level)
```

## Installation

### One-Click Install

```bash
# Global install (all projects)
./install-claude.sh           # → ~/.claude/plugins/vuln-analysis/
./install-codex.sh            # → ~/.codex/

# Local install (current project only)
./install-claude.sh --local   # → ./.claude/plugins/vuln-analysis/
./install-codex.sh --local    # → ./.codex/
```

### Manual Installation

```bash
git clone https://github.com/shaobaobaoer/vuln-analysis-with-validation-plugin.git \
    ~/.claude/plugins/vuln-analysis
```

### Runtime Dependencies

- Docker and docker-compose
- Python 3.12+
- [`uv`](https://github.com/astral-sh/uv) (Python package manager — used inside Docker containers)

## Quick Start

### Full Scan

```
/vuln-scan https://github.com/example/vulnerable-app
```

### Individual Steps

```
/env-setup https://github.com/example/vulnerable-app
/poc-gen
/reproduce
/report
```

### Running PoC Scripts Manually

All PoC execution MUST happen inside Docker:

```bash
cd workspace
docker-compose up -d
docker cp poc_scripts/poc_rce_001.py <container>:/app/
docker exec <container> python3 /app/poc_rce_001.py --target http://localhost:8080 --timeout 30
docker-compose down -v
```

## Supported Vulnerability Types

| Type Key | Description | Validator |
|----------|-------------|-----------|
| `rce` | Remote Code Execution (incl. template-engine SSTI) | `skills/validate-rce/` |
| `ssrf` | Server-Side Request Forgery | `skills/validate-ssrf/` |
| `insecure_deserialization` | Insecure Deserialization | `skills/validate-insecure-deserialization/` |
| `arbitrary_file_rw` | Arbitrary File Read/Write | `skills/validate-arbitrary-file-rw/` |
| `dos` | Denial of Service | `skills/validate-dos/` |
| `command_injection` | Command Injection | `skills/validate-command-injection/` |
| `sql_injection` | SQL / NoSQL Injection | `skills/validate-sql-injection/` |
| `xss` | Cross-Site Scripting (auto-triggering) | `skills/validate-xss/` |
| `idor` | Insecure Direct Object Reference / BOLA | `skills/validate-idor/` |
| `jndi_injection` | JNDI Injection / Log4Shell (**Java only**) | `skills/validate-jndi-injection/` |
| `prototype_pollution` | Prototype Chain Pollution (**JS/TS only**) | `skills/validate-prototype-pollution/` |
| `pickle_deserialization` | Python Pickle RCE (**Python only**) | `skills/validate-pickle-deserialization/` |

## Agents

| Agent | Model | Role |
|-------|-------|------|
| `orchestrator` | opus | Pipeline coordinator — sequences steps, manages state, enforces invariants |
| `analyzer` | opus | Target extraction (Step 1) + vulnerability analysis (Step 4) |
| `builder` | sonnet | Docker environment setup (Step 2) |
| `exploiter` | opus | PoC generation (Step 5) + execution + retry (Steps 6-8) |
| `reporter` | sonnet | Report generation (Step 9) |

## Pipeline Output

```
workspace/
├── target.json              # Step 1: target metadata + entry_points[]
├── Dockerfile               # Step 2: generated Dockerfile
├── docker-compose.yml       # Step 2: compose config
├── vulnerabilities.json     # Step 4: findings with entry_point reachability
├── poc_manifest.json        # Step 5: PoC script manifest
├── poc_scripts/             # Step 5: generated PoC scripts
├── results.json             # Step 7-8: reproduction results
├── pipeline_state.json      # Pipeline progress tracking
└── report/
    ├── REPORT.md            # Step 9: full vulnerability report
    └── summary.json         # Step 9: machine-readable summary
```

## Safety & Ethics

This tool is intended solely for:
- Authorized penetration testing engagements
- CTF competitions and security training
- Defensive security research
- Open-source security auditing

All 9 safety invariants are documented in `agents/orchestrator/AGENT.md §Safety Invariants`. Key rules: Docker-only execution, mandatory steps 1-4, `uv` for Python, local-only builds, label-based cleanup, anti-cheat validation.

Never use this tool against systems without explicit written authorization.
