# vuln-analysis Plugin Memory

## Current State (as of 2026-03-18)

### Supported Vulnerability Types: 8
`rce`, `ssrf`, `insecure_deserialization`, `arbitrary_file_rw`, `dos`, `command_injection`, `sql_injection`, `xss`

**New in this iteration**: `sql_injection` (7th) and `xss` (8th) added.

### Key Architecture
- 9-step pipeline: Target Extraction → Env Setup → Docker Gate → Vuln Analysis → PoC Gen → Env Init → Reproduction → Retry → Report
- Agents: orchestrator (opus), analyzer (opus), builder (sonnet), exploiter (opus), reporter (sonnet)
- All execution inside Docker — NEVER on host
- Python package manager: `uv` exclusively (never pip/conda)

### Recently Fixed Root Causes (from prior iterations)
- Library vs webapp target type confusion (builder creating fake HTTP endpoints for libraries)
- `excluded_findings` key absent in 97% of runs → now mandatory
- `validation_result` schema chaos (7+ field names) → canonical `marker` + `evidence`
- Severity inflation (81% high/critical in 175 runs) → calibration rules added
- `entry_point.access_level = "?"` → forbidden, must be none/auth/admin/local
- `attacker_preconditions = null` → forbidden, must be string
- Report file (REPORT.md) not actually created despite step marked complete

### This Iteration Improvements
1. **sql_injection** type: validator at `skills/validate-sql-injection/SKILL.md` — error-based, time-based blind, boolean-based, union-based
2. **xss** type: validator at `skills/validate-xss/SKILL.md` — reflected + stored, unique marker in response body
3. **CVSS auto-calculation**: `cvss_vector` + `cvss_score` fields now mandatory in every finding
4. **High-value target hunting guide**: Added to vulnerability-scanner for ML serving, LLM stacks, orchestrators, agent frameworks
5. **Retry loop**: Type-specific payload variation strategies for RCE, SQLi, CMDi, SSRF, XSS

### Type Scope by Target Type
- `webapp`: all 8 types
- `service`: all except `xss` (no HTML rendering)
- `cli`: rce, arbitrary_file_rw, dos, command_injection
- `library`: dos, command_injection, insecure_deserialization (network-receiving only)

### Key Quality Gates
- Max 5 findings in `vulnerabilities[]`
- Confidence threshold: >= 7
- No builder-generated entry points
- All types must be one of the 8 supported types
- `disclosures_searched: true` mandatory in filter_summary
- `known_disclosures` key always present (even if `[]`)

### Important File Paths
- Type mapping: `skills/type-mapping.md`
- Validation framework: `templates/validation_framework.md`
- New: SQL validator: `skills/validate-sql-injection/SKILL.md`
- New: XSS validator: `skills/validate-xss/SKILL.md`
