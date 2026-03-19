# Codex Adapter

`codex-adapter/` is the Codex-oriented subproject for the vulnerability-analysis workflow.

It is intentionally self-contained:
- it has its own local `CLAUDE.md`, `agents/`, `commands/`, `skills/`, `templates/`, and `core/`
- it adds Codex-specific `AGENTS.md`, `prompts/`, and `roles/`
- it does not require runtime path references into the sibling `claude-code-plugin/` project

## What Lives Here

The workflow is still instruction-first. The main behavior is driven by local documents rather than a single executable entrypoint:

- `./CLAUDE.md`: root workflow rules and safety invariants
- `./commands/*.md`: copied workflow entrypoints aligned with the Claude command set
- `./agents/*/AGENT.md`: copied agent prompts for orchestrator, analyzer, builder, exploiter, and reporter
- `./skills/*/SKILL.md`: copied operational skills plus Codex-only overlays
- `./templates/*.md`: local prompt templates used by the workflow
- `./core/`: helper runtime code for orchestration, validation, and reporting
- `./AGENTS.md`: Codex-specific skill catalog and operating rules
- `./prompts/*.md`: Codex-native workflow entrypoints
- `./roles/*.md`: Codex-native role briefs for delegated work

## Relationship To The Claude Subproject

This repository contains two sibling subprojects:

- `../claude-code-plugin/`: the Claude Code plugin variant
- `./`: the Codex variant

They are meant to preserve the same workflow content while differing in agent-facing wiring. The Codex subproject should prefer its own local copies when reading skills, commands, and agent docs.

## Codex-Specific Additions

The Codex subproject adds three layers on top of the copied workflow:

| Local layer | Purpose |
|---|---|
| `AGENTS.md` | Codex-facing skill discovery and operating guidance |
| `prompts/` | Codex equivalents of `/vuln-scan`, `/env-setup`, `/poc-gen`, `/reproduce`, `/report` |
| `roles/` | Codex delegation briefs matching the workflow agents |

## New Capability: Template Engine RCE Coverage

This subproject includes `skills/template-engine-rce/`, a local overlay for:

- SSTI and render-from-string paths
- template sandbox escape candidates
- user-controlled expression-string evaluation
- engine-specific PoC generation and validation guidance

The overlay keeps the final vulnerability type as `rce`, but improves classification and filtering with:

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
3. Let Codex follow the local workflow documents under `./CLAUDE.md`, `./commands/`, `./agents/`, and `./skills/`.
4. Keep Codex-specific adjustments in `./prompts/`, `./roles/`, and local overlay skills unless you explicitly want to change the Claude subproject too.

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
├── CLAUDE.md
├── prompts/
├── roles/
├── agents/
├── commands/
├── skills/
│   ├── target-extraction/
│   ├── vulnerability-scanner/
│   ├── poc-writer/
│   ├── validate-*/
│   └── template-engine-rce/
├── templates/
└── core/
```
