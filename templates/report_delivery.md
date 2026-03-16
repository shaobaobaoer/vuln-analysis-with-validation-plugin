# Report Delivery Template

> **Full report structure**: `agents/reporter/AGENT.md`

Compile all findings into a vulnerability report with executive summary, per-vulnerability details, and remediation recommendations.

## Input
- `workspace/target.json`, `workspace/vulnerabilities.json`, `workspace/results.json`, `workspace/poc_manifest.json`

## Report Structure
1. **Executive Summary** — target, risk rating, risk score, finding counts
2. **Reproduction Environment** — copy-paste-ready Dockerfile + build/run commands
3. **Confirmed Vulnerabilities** — per-vulnerability block with:
   - Severity, status, affected component, CVE
   - Entry point (type, path, access level, call chain)
   - **5-part reproduction block**: pre-conditions, PoC execution, expected output, verification, payload
   - Evidence + remediation recommendation
4. **Not Reproduced Findings** — reason + retry history
5. **PoC Scripts Reference** — table + general execution pattern
6. **Appendix** — reproduction logs, validation output

## Output
- `workspace/report/REPORT.md`
- `workspace/report/summary.json` (see `agents/reporter/AGENT.md §summary.json Schema`)
