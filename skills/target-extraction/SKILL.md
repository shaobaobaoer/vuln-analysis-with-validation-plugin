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

## Entry Point Discovery (MANDATORY)

After identifying the project type, enumerate all public entry points. These define the **attack surface** — only vulnerabilities reachable from these entry points are valid.

### By Project Type

**Library** (`type: "library"`):
1. Find the package's public API surface:
   - Python: Read `__init__.py` exports, public functions/classes (no leading `_`)
   - JavaScript: Read `package.json` `main`/`exports`, trace exported symbols
   - Go: Find capitalized (exported) functions/types in package root
   - Java: Find `public` classes and methods
2. List all public functions, classes, and methods
3. Exclude: private/internal functions, test utilities, dev-only helpers

**Web App** (`type: "webapp"`):
1. Find all HTTP route definitions:
   - Flask: `@app.route()`, `@blueprint.route()`
   - Express: `app.get()`, `router.post()`, etc.
   - Django: `urlpatterns`, `path()`, `re_path()`
   - FastAPI: `@app.get()`, `@app.post()`, etc.
   - Spring: `@RequestMapping`, `@GetMapping`, etc.
2. List each endpoint with method, path, and parameters
3. Note authentication requirements (public vs. authenticated vs. admin)

**CLI Tool** (`type: "cli"`):
1. Find the CLI entry point (main function, argument parser):
   - Python: `argparse`, `click`, `typer`, `fire`
   - Go: `cobra`, `flag`, `os.Args`
   - Node: `commander`, `yargs`, `process.argv`
2. List all commands, subcommands, and arguments that accept user input
3. Trace which code paths are reachable from each argument

## Output Schema

> Must align with `agents/analyzer/AGENT.md §workspace/target.json Schema`.

```json
{
  "project_name": "example-project",
  "project_type": "library|webapp|cli",
  "version": "1.2.3",
  "language": "python",
  "framework": "flask",
  "repo_url": "https://github.com/owner/repo",
  "dependencies": ["flask", "requests"],
  "attack_surface": "Description of the attack surface",
  "entry_points": [
    {
      "type": "library_api|webapp_endpoint|cli_command",
      "path": "module.function()|POST /api/exec|tool --input",
      "access_level": "none|auth|admin",
      "parameters": ["param1", "param2"],
      "source_file": "app/views.py:42"
    }
  ]
}
```

**Required fields**: `project_name`, `language`, `entry_points` (non-empty array of objects).

**Field naming**: Use `project_name` (not `name`), `project_type` (not `type` at top level — `type` is reserved for entry point objects).

### Entry Point Fields

| Field | Description |
|-------|-------------|
| `type` | One of: `library_api`, `webapp_endpoint`, `cli_command` |
| `path` | How to invoke: function signature, HTTP endpoint, or CLI syntax |
| `access_level` | `none` (no auth required), `auth` (requires login/token), `admin` (requires admin privileges) |
| `parameters` | User-controllable parameters at this entry point |
| `source_file` | Source file and line where this entry point is defined |

## Best Practices

- Always use `--depth 1` to avoid pulling full history
- Check for existing Dockerfiles in the repo — they indicate the intended runtime
- Look for `.env.example` files to understand required environment variables
- Prefer release tags over HEAD for version identification
- If multiple entry points exist, prioritize the one that starts the main service
- **Entry points define the attack surface** — be thorough in discovery. Missing an entry point may cause valid vulnerabilities to be excluded
- For libraries, check `__init__.py` / `index.js` / package root exports to determine public API boundary
