# Codex Adapter

`codex-adapter/` is the Codex-oriented subproject for the vulnerability-analysis workflow.

It is intentionally self-contained:
- it has its own local `CODEX.md`, `agents/`, `commands/`, `skills/`, `templates/`, and `core/`
- it adds Codex-specific `AGENTS.md`, `prompts/`, and `roles/`
- it does not require runtime path references outside `codex-adapter/`

## What Lives Here

The workflow is still instruction-first. The main behavior is driven by local documents rather than a single executable entrypoint:

- `./CODEX.md`: root workflow rules and safety invariants
- `./commands/*.md`: local workflow entrypoints for the canonical pipeline labels
- `./agents/*/AGENT.md`: local agent prompts for orchestrator, analyzer, builder, exploiter, and reporter
- `./skills/*/SKILL.md`: operational skills plus Codex-side refinements inside the existing workflow
- `./templates/*.md`: local prompt templates used by the workflow
- `./core/`: helper runtime code for orchestration, validation, and reporting
- `./AGENTS.md`: Codex-specific skill catalog and operating rules
- `./prompts/*.md`: Codex-native workflow entrypoints
- `./roles/*.md`: Codex-native role briefs for delegated work

## Codex-Specific Additions

The Codex subproject adds three layers on top of the copied workflow:

| Local layer | Purpose |
|---|---|
| `AGENTS.md` | Codex-facing skill discovery and operating guidance |
| `prompts/` | Codex equivalents of `/vuln-scan`, `/env-setup`, `/poc-gen`, `/reproduce`, `/report` |
| `roles/` | Codex delegation briefs matching the workflow agents |

## New Capability: Template Engine RCE Coverage

Template-engine coverage now lives inside the existing `rce` workflow instead of a standalone skill.
The Codex subproject loads template-engine guidance on demand from:

- `skills/vulnerability-scanner/resources/template-engine-rce.md`
- `skills/code-security-review/resources/template-engine-rce.md`
- `skills/poc-writer/resources/template-engine-rce.md`
- `skills/validate-rce/resources/template-engine-rce.md`

This keeps the final vulnerability type as `rce`, while improving classification and filtering with:

- `engine`
- `template_control`
- `sandbox_mode`
- `dangerous_context`
- `payload_family`

It also explicitly excludes common false positives:

- template-name-only control
- data-only control in a fixed template
- `Markup`, `mark_safe`, or `|safe` cases that are only `xss`

## Recommended Usage

1. Open Codex in `codex-adapter/`.
2. Start from one of the prompt packs in `./prompts/`.
3. Let Codex follow the local workflow documents under `./CODEX.md`, `./commands/`, `./agents/`, and `./skills/`.
4. Keep Codex-specific adjustments in `./prompts/`, `./roles/`, and local skill resources inside this subproject.

## Prompt Packs

- `./prompts/vuln-scan.md`
- `./prompts/env-setup.md`
- `./prompts/poc-gen.md`
- `./prompts/reproduce.md`
- `./prompts/report.md`

## Role Briefs

- `./roles/orchestrator.md`
- `./roles/analyzer.md`
- `./roles/builder.md`
- `./roles/exploiter.md`
- `./roles/reporter.md`

## Local Layout

```text
codex-adapter/
├── AGENTS.md
├── CODEX.md
├── prompts/
├── roles/
├── agents/
├── commands/
├── skills/
│   ├── target-extraction/
│   ├── vulnerability-scanner/
│   ├── poc-writer/
│   ├── validate-*/
│   └── ...
├── templates/
└── core/
```
