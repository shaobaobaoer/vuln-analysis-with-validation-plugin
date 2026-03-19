# Report Delivery Template

> **Full report structure**: `agents/reporter/AGENT.md`

Compile all findings into a vulnerability report with executive summary, per-vulnerability details, prior disclosure cross-references, and remediation recommendations.

## Input
- `workspace/target.json` — project metadata and version
- `workspace/vulnerabilities.json` — findings with `known_disclosures[]` per vulnerability
- `workspace/results.json` — reproduction status
- `workspace/poc_manifest.json` — PoC index (optional)

## Report Structure
1. **Executive Summary** — target, risk rating, risk score, finding counts, disclosure summary
2. **Reproduction Environment** — copy-paste-ready Dockerfile + build/run commands
3. **Confirmed Vulnerabilities** — per-vulnerability block with:
   - Severity, status, affected component, CVE
   - Entry point (type, path, access level, call chain)
   - **Prior Disclosures** — table of matching CVEs / huntr bounties / advisories (or "No prior disclosures found")
   - **5-part reproduction block**: pre-conditions, PoC execution, expected output, verification, payload
   - Evidence + remediation recommendation
4. **Not Reproduced Findings** — reason + retry history
5. **PoC Scripts Reference** — table + general execution pattern
6. **Appendix** — reproduction logs, validation output

## Output
- `workspace/report/REPORT.md`
- `workspace/report/summary.json` — includes `known_disclosures_summary` block with `total_prior_disclosures`, `cve_ids`, `huntr_ids`, `unpatched_in_scanned_version` (see `agents/reporter/AGENT.md §summary.json Schema`)
