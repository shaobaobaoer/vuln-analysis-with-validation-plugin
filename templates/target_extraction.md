# Target Extraction Template

> **Full methodology**: `skills/target-extraction/SKILL.md`

Analyze a GitHub repository to extract target metadata and enumerate all public entry points.

## Input
GitHub repository URL or local project path.

## Key Rules
1. Detect project type: `library` / `webapp` / `cli`
2. Enumerate ALL public entry points — see `CLAUDE.md §Entry Point Reachability` for language-specific rules
3. Exclude private/internal/test-only code from entry points

## Output
`workspace/target.json` — MUST include `project_name`, `project_type`, `version`, `language`, `repo_url`, `framework`, `dependencies`, and `entry_points[]` array (non-empty; each entry has `type`, `path`, `access_level`, `parameters`, `source_file`). See `skills/target-extraction/SKILL.md §Output Schema` for the authoritative field definitions.
