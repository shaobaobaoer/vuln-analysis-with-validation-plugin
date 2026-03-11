---
name: target-extraction
description: Analyze a GitHub repository to identify project type, language, framework, entry points, and extract structured metadata for vulnerability analysis.
origin: vuln-analysis
---

# Target Extraction

Analyze a GitHub repository and extract target metadata for the vulnerability analysis pipeline.

## When to Activate

- User provides a GitHub repository URL for security analysis
- The `/vuln-scan` or `/env-setup` command is invoked
- Target identification is needed before environment setup

## Procedure

1. Clone the repository with `git clone --depth 1`
2. Read key files: README, package manifests, Dockerfiles, entry points
3. Detect tech stack from file extensions and config files:
   - `package.json` → Node.js
   - `requirements.txt` / `pyproject.toml` / `setup.py` → Python
   - `go.mod` → Go
   - `pom.xml` / `build.gradle` → Java
   - `Gemfile` → Ruby
   - `Cargo.toml` → Rust
4. Identify the project type:
   - Has HTTP routes/endpoints → `webapp`
   - Has CLI argument parsing → `cli`
   - Otherwise → `library`
5. Write `workspace/target.json` with extracted metadata

## Output Schema

```json
{
  "name": "string",
  "type": "library|webapp|cli",
  "version": "string",
  "language": "string",
  "repo_url": "string",
  "entry_point": "string",
  "dependencies": ["string"],
  "description": "string",
  "tech_stack": ["string"],
  "exposed_ports": [8080],
  "has_dockerfile": true
}
```

## Best Practices

- Always use `--depth 1` to avoid pulling full history
- Check for existing Dockerfiles in the repo — they indicate the intended runtime
- Look for `.env.example` files to understand required environment variables
- Prefer release tags over HEAD for version identification
- If multiple entry points exist, prioritize the one that starts the main service
