# Vuln-Analysis: Automated Security Vulnerability Verification Plugin

A **Claude Code**, **Cursor**, and **Codex** plugin for automated security vulnerability verification of open-source libraries, web applications, and CLI tools.

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
├── .cursor-plugin/
│   └── plugin.json                        # Cursor IDE plugin manifest (required for Cursor)
├── assets/
│   └── logo.svg                           # Plugin logo (Cursor marketplace)
├── .claude-plugin/
│   ├── plugin.json                        # Claude Code plugin metadata
│   └── marketplace.json                   # Claude Code marketplace listing
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
├── examples/                              # Example PoCs and Dockerfiles
├── README.md                              # This file
├── requirements.txt
├── install-cursor.sh                      # Register repo as Cursor local plugin (~/.cursor/plugins/local/)
├── install-codex.sh                       # Install for Codex (--local for project-level)
└── install-qoder.sh                       # Install for Qoder
```

## Installation

### Cursor

This repository follows the [Cursor plugin layout](https://github.com/cursor/plugin-template): a `.cursor-plugin/plugin.json` manifest at the **plugin root**, plus `commands/`, `agents/`, `skills/`, and `assets/logo.svg`.

**Install (local plugin, recommended for development):**

```bash
git clone https://github.com/shaobaobaoer/vuln-analysis-with-validation-plugin.git
cd vuln-analysis-with-validation-plugin
chmod +x install-cursor.sh
./install-cursor.sh
```

This creates `~/.cursor/plugins/local/vuln-analysis` → this directory. **Restart Cursor** or run **Developer: Reload Window** so the IDE loads the plugin.

**Uninstall:** `rm -f ~/.cursor/plugins/local/vuln-analysis`

See [Using with Cursor](#using-with-cursor) below for day-to-day usage, slash commands, and troubleshooting.

### Claude Code (Recommended)

Use the built-in `plugin` command to install — no install script needed:

```bash
# Global install (all projects)
claude plugin add /path/to/vuln-analysis-with-validation-plugin

# Project-level install (current project only)
claude plugin add --local /path/to/vuln-analysis-with-validation-plugin
```

### Codex

```bash
# Global install
./install-codex.sh            # → ~/.codex/

# Local install (current project only)
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

## Using with Cursor

After [installing the local plugin](#cursor), Cursor loads the manifest in `.cursor-plugin/plugin.json` and exposes the bundled **commands**, **agents**, and **skills** to the AI. You work in the **Agent** or **Chat** panel; behavior follows [Cursor’s plugin documentation](https://cursor.com/docs/plugins).

### Slash commands

1. Open **Agent** or **Chat** in Cursor.
2. Type **`/`** in the input box to open the command palette.
3. Choose a command (file names under `commands/` map to names like `vuln-scan`, `env-setup`, …).

| Command | Purpose |
|---------|---------|
| `/vuln-scan` | Full 9-step pipeline from a GitHub repo URL |
| `/env-setup` | Docker environment setup only |
| `/poc-gen` | PoC generation |
| `/reproduce` | Run reproduction / validation |
| `/report` | Generate the final report |

Example:

```
/vuln-scan https://github.com/example/vulnerable-app
```

Each command file is Markdown with YAML frontmatter (`name`, `description`). The body describes what the agent should do; follow the steps there.

### Agents and skills

- **Agents** live under `agents/*/AGENT.md` (orchestrator, analyzer, builder, exploiter, reporter). Cursor uses them as agent definitions for delegation and routing in the pipeline.
- **Skills** live under `skills/*/SKILL.md`. They activate when the workflow needs that capability (see each command’s “Activation Map” or orchestrator docs).

Model hints in agent frontmatter (e.g. `model: opus`) describe the **original Claude Code** setup. In Cursor, the **model you pick in the UI** applies; treat those fields as guidance, not a hard requirement.

### Updating

Pull the latest code in this repo; the symlink under `~/.cursor/plugins/local/vuln-analysis` still points here, so changes to commands, agents, and skills apply on the next reload. Run **Developer: Reload Window** if Cursor does not pick up edits immediately.

### Troubleshooting

| Issue | What to try |
|-------|-------------|
| `/` does not list plugin commands | Confirm `~/.cursor/plugins/local/vuln-analysis` exists and is a symlink to this repo; restart Cursor or reload the window. |
| Commands appear but behave oddly | Open the matching file in `commands/` and ensure frontmatter `name` / `description` are present. |
| Plugin path moved | Re-run `./install-cursor.sh` from the new location to refresh the symlink. |

For publishing to the **Cursor Marketplace**, see [cursor.com/marketplace/publish](https://cursor.com/marketplace/publish) and the [plugin template](https://github.com/cursor/plugin-template) checklist.

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
