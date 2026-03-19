---
description: Compile all vulnerability findings into a comprehensive Markdown report with executive summary, per-vulnerability details, and remediation recommendations.
---

# /report — Generate Vulnerability Report

Compile all findings into a vulnerability report.

## Usage

```
/report [--format md|json]
```

## Instructions

1. Delegate to the `reporter` agent (`agents/reporter/AGENT.md`)
2. Read all workspace artifacts (target.json, vulnerabilities.json, results.json)
3. Use `templates/report_delivery.md` for report structure guidance
   - If a finding includes template-engine RCE metadata, include the engine, control mode, sandbox status, and payload family in the report narrative
4. Generate:
   - `workspace/report/REPORT.md` — Full Markdown report
   - `workspace/report/summary.json` — Machine-readable summary
5. Copy all artifacts to `workspace/report/` for self-contained delivery

## Report Sections

1. Executive summary with risk rating
2. Per-vulnerability details (description, steps, evidence, remediation)
3. Environment setup instructions
4. PoC scripts reference
5. Appendix with retry history and raw logs
