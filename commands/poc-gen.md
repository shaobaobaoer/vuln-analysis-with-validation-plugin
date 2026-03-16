---
description: Generate Proof-of-Concept exploit scripts for identified vulnerabilities. Each PoC is a standalone Python script with configurable target and timeout.
---

# /poc-gen — Generate PoC Scripts

Generate PoC scripts for vulnerabilities listed in `workspace/vulnerabilities.json`.

## Usage

```
/poc-gen [--vuln-type <type>]
```

## Instructions

1. Read `workspace/vulnerabilities.json`
2. Use `skills/poc-writer/SKILL.md` for script generation patterns
3. For each vulnerability, generate a standalone Python script:
   - Naming: `poc_<type>_<id>.py`
   - Args: `--target`, `--timeout`
   - Exit codes: 0=CONFIRMED, 1=NOT_REPRODUCED, 2=ERROR
4. Write scripts to `workspace/poc_scripts/`
5. Generate `workspace/poc_manifest.json`
6. Validate syntax: `docker exec <container> python3 -m py_compile /app/poc_scripts/<script>` (NEVER run python3 on the host)

## Output

- `workspace/poc_scripts/poc_<type>_<id>.py` per vulnerability
- `workspace/poc_manifest.json`
