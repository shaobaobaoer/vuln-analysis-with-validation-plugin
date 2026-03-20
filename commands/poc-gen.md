---
description: Generate Proof-of-Concept exploit scripts for identified vulnerabilities. Each PoC is a standalone Python script with configurable target and timeout.
---

# /poc-gen — Generate PoC Scripts

Generate PoC scripts for vulnerabilities listed in `workspace/vulnerabilities.json`.

## Usage

```
/poc-gen [--vuln-type <type>]
```

## Activation Map

| Step | Agent | Skills Loaded | Condition |
|------|-------|---------------|-----------|
| 5 — PoC Generation | `exploiter` | `poc-writer` | always |
| — | — | `poc-writer/resources/template-engine-rce.md` | only if finding is `rce` from SSTI/sandbox escape |

## Instructions

1. Read `workspace/vulnerabilities.json`
2. Use `skills/poc-writer/SKILL.md` for script generation patterns
3. For each vulnerability, generate `poc_<type>_<NNN>.py`:
   - Args: `--target`, `--timeout`
   - Exit codes: 0=CONFIRMED, 1=NOT_REPRODUCED, 2=ERROR
4. Write to `workspace/poc_scripts/`
5. Generate `workspace/poc_manifest.json`
6. Validate syntax inside Docker (NEVER `python3` on the host)

## Output

- `workspace/poc_scripts/poc_<type>_<NNN>.py` per vulnerability
- `workspace/poc_manifest.json`
