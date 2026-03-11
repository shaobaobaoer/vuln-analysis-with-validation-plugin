# Vuln-Analysis: Automated Security Vulnerability Verification Plugin

A Claude plugin for automated security vulnerability verification of open-source libraries, web applications, and CLI tools.

> **Authorization Notice**: This tool is designed for authorized security testing, penetration testing engagements, CTF competitions, and defensive security research only.

## Overview

This plugin automates the full vulnerability analysis lifecycle:

1. **Target Extraction** — Analyze a GitHub repository to identify the project type and metadata
2. **Environment Setup** — Auto-detect stack, provision databases, build isolated environment
3. **Vulnerability Analysis** — Scan for known CVEs and code-level vulnerabilities
4. **PoC Generation** — Write exploit scripts for each identified vulnerability
5. **Reproduction** — Execute PoC scripts against the containerized target
6. **Retry Loop** — Auto-fix failures (up to 5 retries per vulnerability)
7. **Validation** — Run type-specific validators for final confirmation
8. **Report Delivery** — Generate a comprehensive Markdown report

## Supported Vulnerability Types

| # | Type | Validator Skill |
|---|------|----------------|
| 1 | Path Traversal | `skills/validate-path-traversal/SKILL.md` |
| 2 | RCE | `skills/validate-rce/SKILL.md` |
| 3 | LFI | `skills/validate-lfi/SKILL.md` |
| 4 | SSRF | `skills/validate-ssrf/SKILL.md` |
| 5 | Insecure Deserialization | `skills/validate-insecure-deserialization/SKILL.md` |
| 6 | IDOR | `skills/validate-idor/SKILL.md` |
| 7 | Arbitrary File R/W | `skills/validate-arbitrary-file-rw/SKILL.md` |
| 8 | DoS | `skills/validate-dos/SKILL.md` |
| 9 | XSS | `skills/validate-xss/SKILL.md` |
| 10 | Command Injection | `skills/validate-command-injection/SKILL.md` |

### Code Security Review

The plugin includes a dedicated code audit skill at `skills/code-security-review/SKILL.md` (integrated from `anthropics/claude-code-security-review`). It enforces a mandatory 3-phase process:

1. **Audit** — Context research, comparative analysis, vulnerability assessment
2. **Filter** — Hard exclusion regex pass, AI filtering (19 rules), precedent check (17 rules), confidence scoring (1-10, threshold >= 7)
3. **Report** — Filter summary table, detailed findings, excluded findings list

All validators and the vulnerability scanner use this framework's confidence scoring and false positive filtering.

## Directory Structure

```
vuln-analysis/
├── CLAUDE.md                              # Project configuration
├── README.md
├── requirements.txt
├── .gitignore
│
├── commands/                              # Slash commands (Claude convention)
│   ├── vuln-scan.md                      #   /vuln-scan — full pipeline
│   ├── env-setup.md                      #   /env-setup — Docker env only
│   ├── poc-gen.md                        #   /poc-gen — generate PoCs
│   ├── reproduce.md                      #   /reproduce — run reproduction
│   └── report.md                         #   /report — generate report
│
├── skills/                                # Skill modules (SKILL.md per skill)
│   ├── code-security-review/             #   3-phase code audit process
│   │   ├── SKILL.md                      #     Mandatory audit → filter → report
│   │   └── resources/                    #     Audit methodology & filtering rules
│   │       ├── audit-prompt.md
│   │       ├── filtering-rules.md
│   │       ├── hard-exclusion-patterns.md
│   │       └── customization-guide.md
│   ├── target-extraction/SKILL.md        #   Step 1: target analysis
│   ├── environment-builder/              #   Step 2: modular env setup
│   │   ├── SKILL.md                      #     Detect → Route → Build → Verify → Document
│   │   ├── app/                          #     Language-specific setup guides
│   │   │   ├── python.md                 #       conda/venv, ML deps, frameworks
│   │   │   ├── node.md                   #       npm/yarn/pnpm, migrations
│   │   │   ├── java.md                   #       Maven/Gradle, Spring Boot
│   │   │   └── docker-compose.md         #       Docker Compose / Dockerfile
│   │   ├── db/                           #     Database container provisioning
│   │   │   ├── postgres.md
│   │   │   ├── mysql.md
│   │   │   ├── redis.md
│   │   │   └── mongo.md
│   │   ├── helpers/                      #     Utility modules
│   │   │   ├── network-check.md          #       Proxy, connectivity, mirror clone
│   │   │   ├── image-check.md            #       Docker image mirror fallback
│   │   │   └── port-isolation.md         #       Free ports, Docker network
│   │   ├── output/
│   │   │   └── status-output.md          #       ENVIRONMENT_SETUP.md template
│   │   └── scripts/                      #     Shell automation
│   │       ├── health_check.sh           #       Web + DB + resource verification
│   │       ├── setup_python_env.sh       #       conda/venv creation + deps
│   │       ├── install_ml_deps.sh        #       ML GPU/CPU dep installer
│   │       ├── install_conda.sh          #       Miniforge auto-installer
│   │       └── env_guard.sh              #       Env drift detection & recovery
│   ├── vulnerability-scanner/SKILL.md    #   Step 3: vuln discovery (with filtering)
│   ├── poc-writer/SKILL.md               #   Step 4: PoC script patterns
│   ├── validate-path-traversal/SKILL.md  #   Validator: path traversal
│   ├── validate-rce/SKILL.md             #   Validator: RCE
│   ├── validate-lfi/SKILL.md             #   Validator: LFI
│   ├── validate-ssrf/SKILL.md            #   Validator: SSRF
│   ├── validate-insecure-deserialization/SKILL.md
│   ├── validate-idor/SKILL.md            #   Validator: IDOR
│   ├── validate-arbitrary-file-rw/SKILL.md
│   ├── validate-dos/SKILL.md             #   Validator: DoS
│   ├── validate-xss/SKILL.md             #   Validator: XSS
│   └── validate-command-injection/SKILL.md
│
├── agents/                                # Agent definitions (flat .md files)
│   ├── orchestrator.md                   #   Pipeline coordinator
│   ├── analyzer.md                       #   Target + vuln analysis
│   ├── builder.md                        #   Docker env builder
│   ├── exploiter.md                      #   PoC execution + retry
│   └── reporter.md                       #   Report generation
│
├── templates/                             # Prompt templates for pipeline steps
│   ├── target_extraction.md
│   ├── environment_setup.md
│   ├── vulnerability_analysis.md
│   ├── poc_generation.md
│   ├── reproduction.md
│   ├── retry_loop.md
│   └── report_delivery.md
│
├── core/                                  # Python framework
│   ├── pipeline.py                       #   Pipeline orchestrator
│   ├── runner.py                         #   PoC script runner
│   ├── validators/
│   │   ├── base.py                       #   Base validator class
│   │   └── registry.py                   #   10 concrete validators
│   ├── reporters/
│   │   ├── markdown.py                   #   Markdown report generator
│   │   └── json_summary.py              #   JSON summary generator
│   └── runners/
│       └── docker_manager.py             #   Docker build/run/cleanup
│
└── examples/
    ├── dockerfiles/
    │   ├── python_webapp.Dockerfile
    │   ├── node_webapp.Dockerfile
    │   └── docker-compose.example.yml
    ├── poc_scripts/                       # One example PoC per vuln type
    │   ├── poc_path_traversal_001.py
    │   ├── poc_rce_001.py
    │   ├── poc_lfi_001.py
    │   ├── poc_ssrf_001.py
    │   ├── poc_insecure_deser_001.py
    │   ├── poc_idor_001.py
    │   ├── poc_arbitrary_file_rw_001.py
    │   ├── poc_dos_001.py
    │   ├── poc_xss_001.py
    │   └── poc_command_injection_001.py
    └── poc_manifest.example.json
```

## Quick Start

### Prerequisites

- Docker and docker-compose installed
- Python 3.12+
- `pip install -r requirements.txt`

### Full Scan

```
/vuln-scan https://github.com/example/vulnerable-app
```

This runs the complete 8-step pipeline and produces all artifacts in `workspace/`.

### Individual Steps

```
/env-setup https://github.com/example/vulnerable-app
/poc-gen
/reproduce
/report
```

### Running PoC Scripts Manually

```bash
cd workspace
docker-compose up -d

python3 poc_scripts/poc_rce_001.py --target http://localhost:8080 --timeout 30

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

## Validation Status Codes

| Status | Exit Code | Meaning |
|--------|-----------|---------|
| `CONFIRMED` | 0 | Vulnerability successfully reproduced |
| `NOT_REPRODUCED` | 1 | Exploit failed, vulnerability not triggered |
| `PARTIAL` | 1 | Some indicators present but not fully exploitable |
| `ERROR` | 2 | Script execution error |
| `MAX_RETRIES` | 1 | Failed after 5 retry attempts |

## Security & Ethics

This tool is intended solely for:
- Authorized penetration testing engagements
- CTF competitions and security training
- Defensive security research
- Open-source security auditing

Never use this tool against systems without explicit written authorization.
