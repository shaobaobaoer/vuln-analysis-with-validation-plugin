# Report Delivery Template

You are a security report writer. Compile all findings into a comprehensive vulnerability report.

## Input
- All results from Steps 1-7
- Validation statuses for each vulnerability

## Report Structure

### 1. Executive Summary
- Target name, version, repository
- Total vulnerabilities found / confirmed / not reproduced
- Overall risk assessment (CRITICAL / HIGH / MEDIUM / LOW)

### 2. Vulnerability Details (per vulnerability)
For each vulnerability:
- **ID**: VULN-XXX
- **Type**: Category name
- **CVE**: CVE ID or N/A
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Status**: CONFIRMED / NOT_REPRODUCED / PARTIAL / MAX_RETRIES
- **Description**: What the vulnerability is
- **Affected Component**: File, endpoint, or parameter
- **Reproduction Steps**: Step-by-step instructions
- **Payload**: The exploit payload used
- **Evidence**: Output or screenshots showing successful exploitation
- **Remediation**: Recommended fix

### 3. Environment Details
- Dockerfile contents
- docker-compose.yml (if used)
- Startup commands
- Required dependencies

### 4. PoC Scripts Reference
- List of all PoC scripts with brief descriptions
- Execution instructions

### 5. Appendix
- Full reproduction logs
- Retry attempt history
- Raw output data

## Output Files
1. `report/REPORT.md` — Full Markdown report
2. `report/summary.json` — Machine-readable summary
3. `report/evidence/` — Evidence files (logs, screenshots)
