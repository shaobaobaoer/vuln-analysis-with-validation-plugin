---
description: Compile all vulnerability findings into a comprehensive Markdown report with executive summary, per-vulnerability details, and remediation recommendations.
---

# /report — Generate Vulnerability Report

Compile all findings into a vulnerability report.

## Usage

```
/report [--format md|json]
```

## Activation Map

| Step | Agent | Skills Loaded | Condition |
|------|-------|---------------|-----------|
| 9 — Report | `reporter` | — | always |

No type-specific skills are loaded. The reporter reads workspace artifacts directly.

## Instructions

1. Delegate to `agents/reporter/AGENT.md`
2. Read all workspace artifacts (`target.json`, `vulnerabilities.json`, `results.json`)
3. Use `agents/reporter/resources/report_delivery.md` for report structure
4. Generate `workspace/report/REPORT.md` and `workspace/report/summary.json`

## Report Sections

1. Executive summary with risk rating
2. Per-vulnerability details (description, steps, evidence, remediation)
3. Environment setup instructions
4. PoC scripts reference
5. Appendix with retry history and raw logs
