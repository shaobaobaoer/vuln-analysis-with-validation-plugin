# Vuln-Analysis: Automated Security Vulnerability Verification Plugin

A Claude Code plugin for automated security vulnerability verification of open-source libraries, web applications, and CLI tools.

> **Authorization Notice**: This tool is designed for authorized security testing, penetration testing engagements, CTF competitions, and defensive security research only.

> **Monorepo note**: In this repository, the Claude variant lives under `claude-code-plugin/`. The sibling `codex-adapter/` directory is a separate Codex-oriented subproject with the same workflow content but different agent wiring.

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

## Key Features

### Entry Point Reachability

A vulnerability is only valid if an attacker can **reach** it through a public entry point. The pipeline enforces this at every stage:

| Target Type | Valid Entry Points |
|-------------|-------------------|
| **Library** | Public API functions/classes/methods |
| **Web App** | HTTP routes, API endpoints, WebSocket handlers |
| **CLI Tool** | CLI commands and arguments |

Unreachable vulnerabilities (private functions, test files, dead code) are automatically excluded.

### Anti-Cheat Validation

Every PoC undergoes a **legitimacy check** to ensure it exploits through the target application's vulnerable code path — not by directly calling system APIs. This prevents false confirmations.

### Docker-Only Execution

All PoC scripts and Python execution happen **inside Docker containers**. Nothing runs on the host except Docker management commands. All Docker resources are labeled with `vuln-analysis.pipeline-id` for safe, targeted cleanup.

### Template Engine RCE Coverage

Template-engine coverage now lives inside the existing `rce` workflow instead of a standalone skill.
The workflow loads template-engine guidance on demand from:

- `skills/vulnerability-scanner/resources/template-engine-rce.md`
- `skills/code-security-review/resources/template-engine-rce.md`
- `skills/poc-writer/resources/template-engine-rce.md`
- `skills/validate-rce/resources/template-engine-rce.md`

This covers:

- server-side template injection and render-from-string sinks
- sandbox escape candidates in template engines
- user-controlled expression-string evaluation
- engine-specific payload selection for Jinja2, Mako, Django templates, FreeMarker, Velocity, Thymeleaf/SpEL, EJS, Pug, Nunjucks, Handlebars, and Go `text/template`

The feature keeps the top-level vulnerability type as `rce`, but adds better filtering so the workflow excludes:

- template-name-only control
- fixed-template data-only control
- `Markup`, `mark_safe`, and `|safe` cases that are actually `xss`

## Supported Vulnerability Types

| Type Key | Description | Validator |
|----------|-------------|-----------|
| `rce` | Remote Code Execution, including template-engine render and sandbox-escape paths | `skills/validate-rce/` |
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
| `pickle_deserialization` | Python Pickle RCE via `__reduce__` (**Python only**) | `skills/validate-pickle-deserialization/` |

### Code Security Review

The plugin includes a mandatory 3-phase code audit process at `skills/code-security-review/`:

1. **Audit** — Context research, comparative analysis, vulnerability assessment
2. **Filter** — Hard exclusion regex, AI filtering (30 rules incl. JNDI + PP language-gated quality gates), precedent check (22+ rules), confidence scoring (threshold >= 7)
3. **Report** — Filter summary table, detailed findings, excluded findings list

### Template Engine RCE Metadata

The existing `rce` workflow classifies template-engine findings with:

- `engine`
- `template_control`
- `sandbox_mode`
- `dangerous_context`
- `payload_family`

It is intended for SSTI and sandbox-escape analysis only. It does not introduce a new top-level vulnerability type.

## Architecture

### Agents

| Agent | Model | Role |
|-------|-------|------|
| `orchestrator` | opus | Pipeline coordinator — sequences steps, manages state, enforces invariants |
| `analyzer` | opus | Target extraction (Step 1) + vulnerability analysis (Step 4) |
| `builder` | sonnet | Docker environment setup (Step 2) |
| `exploiter` | opus | PoC generation (Step 5) + execution + retry (Steps 6-8) |
| `reporter` | sonnet | Report generation (Step 9) |

### Documentation Hierarchy

```
CLAUDE.md                    ← Root rules (safety invariants, conventions)
  ├── agents/*/AGENT.md      ← Agent-specific workflows (reference CLAUDE.md for shared rules)
  ├── skills/*/SKILL.md      ← Detailed operational guides (authoritative per topic)
  └── templates/*.md         ← Lightweight entry points (reference skills/agents)
```

Each piece of information has **one authoritative location**. Templates are thin references; skills contain full methodology.

## Directory Structure

```
claude-code-plugin/
├── CLAUDE.md                              # Project rules and conventions
├── README.md
├── requirements.txt
├── .gitignore
│
├── commands/                              # Slash commands
│   ├── vuln-scan.md                       #   /vuln-scan — full 9-step pipeline
│   ├── env-setup.md                       #   /env-setup — Docker env only
│   ├── poc-gen.md                         #   /poc-gen — generate PoCs
│   ├── reproduce.md                       #   /reproduce — run reproduction
│   └── report.md                          #   /report — generate report
│
├── skills/                                # Skill modules
│   ├── target-extraction/SKILL.md         #   Step 1: target + entry point analysis
│   ├── environment-builder/               #   Step 2: modular env setup
│   │   ├── SKILL.md                       #     Detect → Route → Build → Verify → Document
│   │   ├── app/                           #     Language-specific (python, node/ts, java, go, docker-compose)
│   │   ├── db/                            #     Database provisioning (postgres, mysql, redis, mongo)
│   │   ├── helpers/                       #     Network check, image check, port isolation
│   │   ├── output/                        #     ENVIRONMENT_SETUP.md template
│   │   └── scripts/                       #     Shell automation (health check, env setup)
│   ├── vulnerability-scanner/SKILL.md     #   Step 4: vuln discovery with filtering
│   ├── code-security-review/              #   3-phase code audit
│   │   ├── SKILL.md                       #     Mandatory audit → filter → report
│   │   └── resources/                     #     Filtering rules, exclusion patterns
│   ├── poc-writer/SKILL.md                #   Step 5: PoC script patterns
│   └── validate-*/SKILL.md               #   12 type-specific validators (Steps 7-8; 3 are language-gated)
│
├── agents/                                # Agent definitions
│   ├── orchestrator/AGENT.md              #   Pipeline coordinator (opus)
│   ├── analyzer/AGENT.md                  #   Target + vuln analysis (opus)
│   ├── builder/AGENT.md                   #   Docker env builder (sonnet)
│   ├── exploiter/AGENT.md                 #   PoC execution + retry (opus)
│   └── reporter/AGENT.md                  #   Report generation (sonnet)
│
├── templates/                             # Lightweight prompt templates
│   ├── validation_framework.md            #   Unified PoC validation framework (authoritative)
│   └── *.md                               #   Thin references to skills/agents
│
├── core/                                  # Python framework
│   ├── pipeline.py                        #   Pipeline orchestrator
│   ├── runner.py                          #   PoC script runner
│   ├── validators/                        #   Base + 11 concrete validators (2 language-gated)
│   ├── reporters/                         #   Markdown + JSON report generators
│   └── runners/                           #   Docker manager
│
└── examples/
    ├── dockerfiles/                        #   Example Docker configs
    ├── poc_scripts/                        #   Example PoC scripts per vuln type
    └── poc_manifest.example.json
```

## Installation

### Via Claude Code Plugin (Recommended)

```bash
claude plugin marketplace add shaobaobaoer/vuln-analysis-with-validation-plugin
claude plugin install vuln-analysis@vuln-analysis-with-validation-plugin
```

### Manual Installation

```bash
git clone https://github.com/shaobaobaoer/vuln-analysis-with-validation-plugin.git \
    ~/.claude/plugins/vuln-analysis
```

If you are working from this repository layout directly, the Claude plugin project root is:

```bash
cd ~/.claude/plugins/vuln-analysis/claude-code-plugin
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

This runs the complete 9-step pipeline and produces all artifacts in `workspace/`.

When template rendering is attacker-controlled, the pipeline should classify the finding as `rce` and load the embedded template-engine guidance inside the existing `rce` workflow rather than inventing a separate type.

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

# Copy PoC into container and execute (NEVER run python3 on the host)
docker cp poc_scripts/poc_rce_001.py <container>:/app/
docker exec <container> python3 /app/poc_rce_001.py --target http://localhost:8080 --timeout 30

docker-compose down -v
```

### Using the Python Framework

```python
from core.pipeline import VulnPipeline

pipeline = VulnPipeline(
    repo_url="https://github.com/example/vulnerable-app",
    workspace="./workspace"
)
pipeline.run()
```

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

## Validation Status Codes

| Status | Exit Code | Meaning |
|--------|-----------|---------|
| `CONFIRMED` | 0 | Vulnerability successfully reproduced |
| `NOT_REPRODUCED` | 1 | Exploit failed, vulnerability not triggered |
| `PARTIAL` | 1 | Some indicators present but not fully exploitable |
| `ERROR` | 2 | Script execution error |
| `MAX_RETRIES` | 1 | Failed after 5 retry attempts |

## Safety & Ethics

> See `CLAUDE.md §Safety Invariants` for the full 9 rules (Docker-only execution, mandatory steps, uv, local-only builds, label-based cleanup, anti-cheat).

This tool is intended solely for:
- Authorized penetration testing engagements
- CTF competitions and security training
- Defensive security research
- Open-source security auditing

Never use this tool against systems without explicit written authorization.
