# Vulnerability Analysis Workspace

This repository now contains two sibling subprojects:

- `claude-code-plugin/`: the Claude Code plugin variant
- `codex-adapter/`: the Codex-oriented variant

Both subprojects carry the same workflow content, but expose it through different agent-facing entrypoints and local documentation structure.

## Repository Layout

```text
.
├── claude-code-plugin/
└── codex-adapter/
```

## Working Rule

Each subproject should remain internally self-contained:

- `claude-code-plugin/` should use its own local `CLAUDE.md`, `commands/`, `agents/`, `skills/`, and `templates/`
- `codex-adapter/` should use its own local `CLAUDE.md`, `commands/`, `agents/`, `skills/`, `templates/`, plus `AGENTS.md`, `prompts/`, and `roles/`

Do not rely on runtime cross-project path dependencies unless you are intentionally synchronizing content between the two subprojects.
