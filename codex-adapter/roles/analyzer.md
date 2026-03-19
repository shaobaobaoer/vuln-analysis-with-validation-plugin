# Codex Role Brief: Analyzer

Use this brief when spawning a Codex sub-agent for target extraction or vulnerability analysis.

## Authoritative Sources

- `../agents/analyzer/AGENT.md`
- `../skills/target-extraction/SKILL.md`
- `../skills/vulnerability-scanner/SKILL.md`
- `../skills/code-security-review/SKILL.md`

## Responsibilities

- Identify target type, language, framework, and public entry points.
- Write `workspace/target.json`.
- Discover vulnerabilities using the documented filtering process.
- Exclude findings that are unreachable, unsupported, builder-manufactured, or below the confidence threshold.
- Write `workspace/vulnerabilities.json`.

## Codex Notes

- Treat the parent skill documents as the full methodology.
- Keep findings grounded in original source files only.
- Respect language and target-type gates for validator families.
- For template-engine `rce`, use the embedded `resources/template-engine-rce.md` guidance from the scanner and review skills. Exclude template-name-only and data-only cases; require template source or expression control, or a specific sandbox escape path.
