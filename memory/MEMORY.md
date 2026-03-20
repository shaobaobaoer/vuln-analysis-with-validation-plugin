# vuln-analysis Plugin Memory

## Current State (as of 2026-03-18, v1.9.2)

### Supported Vulnerability Types: 12

**9 base types** (all languages):
`rce`, `ssrf`, `insecure_deserialization`, `arbitrary_file_rw`, `dos`, `command_injection`, `sql_injection`, `xss`, `idor`

**3 language-gated types** (only scan/validate when language matches):
- `jndi_injection` — **Java only** (Log4Shell CVE-2021-44228, CVSS 10.0); TCP callback on port 59877
- `prototype_pollution` — **JavaScript/TypeScript only** (`__proto__` deep-merge → EJS/Pug/Handlebars gadget → RCE CVSS 8.1 or privesc CVSS 6.5)
- `pickle_deserialization` — **Python only** (`pickle.loads()` over network HTTP/socket → `__reduce__` RCE CVSS 9.8); marker `/tmp/pickle_rce_<id>`

### Key Architecture
- **9-step pipeline**: Target Extraction → Env Setup → Docker Gate → Vuln Analysis → PoC Gen → Env Init → Reproduction → Retry → Report
- **Agents**: orchestrator (opus), analyzer (opus), builder (sonnet), exploiter (opus), reporter (sonnet)
- **All execution inside Docker** — NEVER on host
- **Python package manager**: `uv` exclusively (never pip/conda)
- **Stage-activation gates**: validators activate Steps 7-8 ONLY; language-gated validators only for matching language

### Type Scope by Target Type
- `webapp`: all 12 types with language gating (idor: integer-keyed only; jndi: Java; PP: JS/TS; pickle: Python)
- `service`: all except xss and idor (+ language-gated types where applicable)
- `cli`: rce, arbitrary_file_rw, dos, command_injection
- `library`: dos, command_injection, insecure_deserialization (network-receiving only), prototype_pollution (JS/TS deep-merge libs only)

### Language Coverage (Dockerfile templates + scan patterns)

| Language | Dockerfile Template | Framework Patterns | Language-Gated Type |
|----------|--------------------|--------------------|---------------------|
| Python | `app/python.md` (uv + slim) | django, fastapi, flask | `pickle_deserialization` |
| TypeScript/JS | `app/node.md` (multi-stage TS) | express, nestjs | `prototype_pollution` |
| Java | `app/java.md` (Maven/Gradle multi-stage) | spring-boot | `jndi_injection` |
| Go | `app/go.md` (alpine multi-stage) | go-gin | — |

### Stage-Activation Gates (ENFORCED — see orchestrator/AGENT.md)
- **Step 1 only**: `target-extraction`
- **Step 2 only**: `environment-builder` (generates Dockerfiles, never runs analysis)
- **Step 3 only**: Docker CLI health check
- **Step 4 only**: `vulnerability-scanner` + `code-security-review`
- **Step 5 only**: `poc-writer`
- **Step 6 only**: Docker CLI (TCP listeners, trigger binary)
- **Steps 7-8 only**: `validate-<type>` matching each vuln's type; language-gated validators only for matching language
- **Step 9 only**: reporter agent

### Key Quality Gates
- Max 5 findings in `vulnerabilities[]`
- Confidence threshold: >= 7
- All types must be one of the 12 supported (language-gated enforced)
- `disclosures_searched: true` mandatory
- `known_disclosures` key always present (even if `[]`)
- `cvss_vector` + `cvss_score` mandatory on every finding
- No builder-generated entry points in findings
- IDOR: UUID-keyed excluded (Precedent #2); ownership check must be absent
- XSS: only auto-triggering (reflected on nav, stored on page load)
- pickle_deserialization: network path to `pickle.loads()` required; local file loading excluded

### Language Detection Values (target.json → language field — EXACT STRINGS)

| Config File | `language` value | Gate triggers |
|---|---|---|
| `tsconfig.json` or >50% `.ts` files | `"typescript"` | `prototype_pollution`, `validate-prototype-pollution` |
| `package.json` only (no tsconfig) | `"javascript"` | `prototype_pollution`, `validate-prototype-pollution` |
| `requirements.txt` / `pyproject.toml` / `setup.py` | `"python"` | `pickle_deserialization`, `validate-pickle-deserialization` |
| `pom.xml` / `build.gradle` | `"java"` | `jndi_injection`, `validate-jndi-injection` |
| `go.mod` | `"go"` | no language-specific type |
| `Gemfile` | `"ruby"` | no language-specific type |

### Root Causes Fixed (175+ pipeline runs)
- Library targets: builder was creating fake HTTP endpoints → manufactured vulnerabilities → anti-cheat rules added
- Duplicate `_ALL_VALIDATORS` in registry.py → first 9 were overwritten → fixed
- `excluded_findings` key absent → now mandatory
- `validation_result` schema chaos (7+ field names) → canonical `marker` + `evidence`
- Severity inflation (81% high/critical) → CVSS calibration rules added
- Language-wrong type findings (JNDI for Python, pickle for Java) → Phase 0.5 Language Gate added
- target.json `language` field values were ambiguous (TypeScript vs JavaScript) → explicit detection table added with exact string values
- filtering-rules.md Rule 26 was missing (gap 25→27) → URL-path vs filesystem-path traversal rule added
- Stale rule count "28/30/31 filtering rules" in 4 files → all corrected to 33

### Important File Paths
- Type mapping: `skills/type-mapping.md` (12 types, mapping rules, EXCLUDE list)
- Filtering rules: `skills/code-security-review/resources/filtering-rules.md` (33 rules: Rules 1-27 general hard exclusions, Rules 28-33 type-specific quality gates; Rule 26 = URL-path vs filesystem-path traversal disambiguation)
- Validation framework: `skills/_shared/validation_framework.md`
- Language grep patterns: `skills/vulnerability-scanner/resources/language-grep-patterns.md`
- Static analysis patterns: `skills/vulnerability-scanner/resources/static-analysis-patterns.md`
- Validators: `skills/validate-*/SKILL.md` (12 validators)
- Framework patterns: `skills/vulnerability-scanner/resources/framework-patterns/` (9 files)
- Retry strategies: `agents/exploiter/resources/retry-strategies.md`

### Example Coverage (complete as of v1.9.2)

**PoC Scripts** (`examples/poc_scripts/`) — all 12 types, all files exist:
- Base (9): `poc_rce_001.py`, `poc_ssrf_001.py`, `poc_insecure_deser_001.py`, `poc_arbitrary_file_rw_001.py`, `poc_dos_001.py`, `poc_command_injection_001.py`, `poc_sql_injection_001.py`, `poc_xss_001.py`, `poc_idor_001.py`
- Language-gated (3): `poc_jndi_injection_001.py` (Java/CVSS 10.0), `poc_prototype_pollution_001.py` (JS/TS/CVSS 8.1), `poc_pickle_deserialization_001.py` (Python/CVSS 9.8)

**Dockerfile Examples** (`examples/dockerfiles/`):
- `python_webapp.Dockerfile` — uv + slim, Python/Flask/FastAPI/Django
- `node_webapp.Dockerfile` — multi-stage TypeScript/JS, NestJS/Express
- `java_webapp.Dockerfile` — Maven + eclipse-temurin multi-stage, Spring Boot Actuator healthcheck
- `go_webapp.Dockerfile` — alpine multi-stage, CGO_ENABLED=0 static binary, wget healthcheck
- `docker-compose.example.yml` — multi-service composition

**Manifest**: `examples/poc_manifest.example.json` — all 12 types with cvss_vector, cvss_score, language_gate
