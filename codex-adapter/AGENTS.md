# Codex Adapter Instructions

This directory is a self-contained Codex-facing variant of the vulnerability analysis workflow. It keeps its own local workflow assets alongside Codex-specific wrappers.

## Project Summary

- This repo is primarily an instruction-driven security workflow, not just a Python package.
- The main behavior lives in `./CLAUDE.md`, `./commands/*.md`, `./agents/*/AGENT.md`, and `./skills/*/SKILL.md`.
- `./core/` is a helper runtime library for reports, Docker orchestration, and validation; it does not replace the documented multi-agent workflow.
- Default Codex-specific writes should stay inside this directory or the runtime `workspace/` output tree.

## Non-Invasive Policy

- Treat `./CLAUDE.md`, `./commands/`, `./agents/`, and the copied base skills under `./skills/` as the local authoritative workflow for the Codex subproject.
- Put Codex-only instructions, wrappers, and prompt packs in this directory.
- Keep Codex-specific overlays and role adapters additive instead of editing the copied workflow more than necessary.

## Skills

A skill is a set of local instructions to follow that is stored in a `SKILL.md` file. Below is the list of skills that are relevant when operating this plugin from Codex.

### Available skills

- `target-extraction`: Detect target type, language, framework, and public entry points, then write `workspace/target.json`. (file: `./skills/target-extraction/SKILL.md`)
- `environment-builder`: Detect stack, build Docker environment, verify health, and write `ENVIRONMENT_SETUP.md`. (file: `./skills/environment-builder/SKILL.md`)
- `vulnerability-scanner`: Perform CVE lookup and static discovery with reachability and confidence scoring. (file: `./skills/vulnerability-scanner/SKILL.md`)
- `code-security-review`: Run the mandatory audit-filter-report pass that removes false positives. (file: `./skills/code-security-review/SKILL.md`)
- `poc-writer`: Generate standalone PoC scripts, manifests, and canonical result records. (file: `./skills/poc-writer/SKILL.md`)
- `template-engine-rce`: Codex-side overlay for SSTI, template sandbox escape, and template-string-controlled render/compile paths that lead to command execution. Use alongside scanner/review/poc/validate-rce when template source or expression strings are attacker-controlled. (file: `./skills/template-engine-rce/SKILL.md`)
- `validate-rce`: Validate remote code execution through the real target path. (file: `./skills/validate-rce/SKILL.md`)
- `validate-ssrf`: Validate outbound server-side request forgery with callback evidence. (file: `./skills/validate-ssrf/SKILL.md`)
- `validate-insecure-deserialization`: Validate non-pickle insecure deserialization findings. (file: `./skills/validate-insecure-deserialization/SKILL.md`)
- `validate-arbitrary-file-rw`: Validate arbitrary file read or write behavior and evidence. (file: `./skills/validate-arbitrary-file-rw/SKILL.md`)
- `validate-dos`: Validate denial-of-service findings with baseline and degraded behavior. (file: `./skills/validate-dos/SKILL.md`)
- `validate-command-injection`: Validate command injection findings with trigger evidence. (file: `./skills/validate-command-injection/SKILL.md`)
- `validate-sql-injection`: Validate SQL or NoSQL injection via the exposed entry point. (file: `./skills/validate-sql-injection/SKILL.md`)
- `validate-xss`: Validate auto-triggering XSS only. (file: `./skills/validate-xss/SKILL.md`)
- `validate-idor`: Validate integer-keyed IDOR/BOLA issues with cross-user access checks. (file: `./skills/validate-idor/SKILL.md`)
- `validate-jndi-injection`: Validate JNDI injection for Java targets only. (file: `./skills/validate-jndi-injection/SKILL.md`)
- `validate-prototype-pollution`: Validate prototype pollution for JavaScript/TypeScript targets only. (file: `./skills/validate-prototype-pollution/SKILL.md`)
- `validate-pickle-deserialization`: Validate Python pickle deserialization over a network-reachable path. (file: `./skills/validate-pickle-deserialization/SKILL.md`)

### How to use skills

- After deciding to use a skill, open its `SKILL.md` and read only the parts needed for the current task.
- Prefer the copied local skill documents under `./skills/` over re-explaining their guidance in new files.
- Use `./skills/template-engine-rce/SKILL.md` as an override layer when the task involves SSTI, template sandbox escape, Jinja2/Mako/FreeMarker/Velocity/Thymeleaf/EJS/Pug/Nunjucks/Handlebars, or user-controlled template strings.
- Use the minimal skill set that covers the request. For a full scan this is usually `target-extraction`, `environment-builder`, `vulnerability-scanner`, `code-security-review`, `poc-writer`, and one or more `validate-*` skills.
- Respect the original stage gates: scanning belongs to Step 4, PoC writing to Step 5 or retry rewrites, validators to Steps 7-8, and reporting to Step 9.
- If the user names a workflow such as `vuln-scan`, `env-setup`, `poc-gen`, `reproduce`, or `report`, open the matching prompt pack in `./prompts/` first.

## Prompt Packs

- `./prompts/vuln-scan.md`: Codex entry for the full 9-step pipeline.
- `./prompts/env-setup.md`: Codex entry for target extraction plus Docker environment setup.
- `./prompts/poc-gen.md`: Codex entry for PoC generation from `workspace/vulnerabilities.json`.
- `./prompts/reproduce.md`: Codex entry for execution, validation, and retry handling.
- `./prompts/report.md`: Codex entry for final report generation.

When a prompt pack is named, use it as the starting workflow and then read the original source documents it references.

## Role Briefs

- `./roles/orchestrator.md`: Codex-side coordinator for the 9-step pipeline.
- `./roles/analyzer.md`: Target extraction and vulnerability analysis specialist.
- `./roles/builder.md`: Docker environment builder and fixer.
- `./roles/exploiter.md`: PoC generation, execution, and retry specialist.
- `./roles/reporter.md`: Markdown and JSON report specialist.

When using `spawn_agent`, pass the matching role brief and cite the local `./agents/*/AGENT.md` file as the authoritative source.
