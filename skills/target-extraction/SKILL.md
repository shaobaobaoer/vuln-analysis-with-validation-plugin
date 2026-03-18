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
4. **Classify project type** — see §Target Type Classification below
5. **Assess network attack surface** — see §Network Attack Surface Assessment below
6. Write `workspace/target.json` with extracted metadata

---

## Target Type Classification (MANDATORY)

This is the most critical step. Getting the type wrong causes the entire pipeline to produce invalid findings.

| Type | Definition | Detection Signal |
|------|------------|-----------------|
| `webapp` | Ships its own HTTP server; accepts requests over a network port | Route definitions in source (`@app.route`, `router.get`, `urlpatterns`, `@Controller`); `app.run()` / `uvicorn.run()` / `app.listen()` in entrypoint |
| `service` | Network daemon or RPC server (non-HTTP) — ML serving, gRPC, distributed coordination | `grpc.server()`, `torch.distributed`, Triton/TFX/Seldon server code, ZMQ/socket `bind()` in main loop |
| `cli` | Command-line tool; no network server; invoked with arguments | `argparse`, `click`, `cobra`, `os.Args`, `process.argv` as primary entry point |
| `library` | Importable package/SDK with no own HTTP server or daemon | Only `def` / `class` definitions; no `app.run()`, no route decorators, no `socket.bind()` in the package's own code |

**Detection rules** (check in this order):
1. Search the source root for `@app.route`, `@router.get/post`, `urlpatterns =`, `@RequestMapping`, `app.listen(`, `grpc.server(` → `webapp` or `service`
2. Search for `if __name__ == '__main__':` that calls `app.run()`, `uvicorn.run()`, `serve(`, `listen(` → `webapp` or `service`
3. Search for `argparse.ArgumentParser()`, `@click.command()`, `cobra.Command{}` as primary entry → `cli`
4. If none of the above → `library`

**Important**: A library that has an `examples/server.py` or `tests/test_server.py` is still a `library`. The HTTP server must be in the library's own importable package code, not in examples or tests.

---

## Network Attack Surface Assessment (MANDATORY)

For every target, explicitly assess whether an attacker can reach the vulnerable code WITHOUT any intermediary application.

### `network_exploitable` field

Set `network_exploitable: true` ONLY if ALL of these are true:
1. The target runs its own network-accessible service (HTTP, gRPC, TCP, etc.)
2. That service is defined in the original repository source code (not added by builder)
3. An attacker can send crafted input to that service without controlling intermediate application code

Set `network_exploitable: false` if:
- Target is a `library` or `cli` (no built-in server)
- The only way to exploit requires passing user input through a calling application
- The attack surface only exists if a developer "misuses" the library

### Vulnerability Type Scope

Based on target type, set `valid_vuln_types[]` — the pipeline will ONLY analyze for types in this list:

| Target Type | Valid Vulnerability Types | Rationale |
|-------------|--------------------------|-----------|
| `webapp` | `rce`, `ssrf`, `insecure_deserialization`, `arbitrary_file_rw`, `dos`, `command_injection` | All types in scope — attacker can reach code via HTTP |
| `service` | `rce`, `insecure_deserialization`, `arbitrary_file_rw`, `dos`, `command_injection` | No HTTP → no SSRF; other types valid if service protocol exposed |
| `cli` | `rce`, `arbitrary_file_rw`, `dos`, `command_injection` | Attacker controls CLI args/input files; SSRF/deser rarely valid |
| `library` | `dos`, `command_injection`, `insecure_deserialization`* | **Severely restricted** — see §Library Target Rules below |

### Library Target Rules

For `library` type targets, the following restrictions apply:

**`dos` — valid only if**:
- Single crafted input to a public API function causes algorithmic slowdown (ReDoS, quadratic complexity, XML bomb)
- No flooding required; single call is sufficient
- Example: `lib.tokenize(crafted_string)` hangs due to regex catastrophic backtracking

**`command_injection` — valid only if**:
- The library's own source code calls `subprocess.run(cmd, shell=True)` or `os.system(cmd)` where `cmd` includes a parameter that a caller can control
- Example: `lib.compile(source_path)` → `os.system(f"cc {source_path}")` where source_path goes unescaped
- NOT valid if the injection requires the calling application to construct the shell command

**`insecure_deserialization` — valid only if**:
- The library itself (not a wrapper) receives serialized bytes over a **network protocol** (socket, HTTP client, RPC) and deserializes them
- Example: A library with a built-in TCP server that receives pickle data from clients
- NOT valid if the library reads a local file whose path the caller provides — that requires local access

**`rce`, `ssrf`, `arbitrary_file_rw` — NOT valid for pure library targets** unless:
- The library ships a standalone HTTP server component (then treat it as `webapp`)
- The specific public API function directly reads from a URL or network socket under caller-supplied input

**When all valid types are excluded**: If no vulnerabilities of the valid types exist, write `vulnerabilities: []` and note in `filter_summary` that the target type scope eliminates all candidate findings. Do NOT manufacture an HTTP server to find something.

---

## Entry Point Discovery (MANDATORY)

After classifying the project type, enumerate all public entry points. These define the **attack surface** — only vulnerabilities reachable from these entry points are valid.

### By Project Type

**Library** (`type: "library"`):
1. Find the package's public API surface:
   - Python: Read `__init__.py` exports, public functions/classes (no leading `_`)
   - JavaScript: Read `package.json` `main`/`exports`, trace exported symbols
   - Go: Find capitalized (exported) functions/types in package root
   - Java: Find `public` classes and methods
2. List all public functions, classes, and methods
3. Exclude: private/internal functions, test utilities, dev-only helpers
4. **All entry points get `access_level: "local"`** — a library function is called by application code on the same host

**Web App** (`type: "webapp"`):
1. Find all HTTP route definitions in the **original source** (not examples, not tests):
   - Flask: `@app.route()`, `@blueprint.route()`
   - Express: `app.get()`, `router.post()`, etc.
   - Django: `urlpatterns`, `path()`, `re_path()`
   - FastAPI: `@app.get()`, `@app.post()`, etc.
   - Spring: `@RequestMapping`, `@GetMapping`, etc.
2. List each endpoint with method, path, and parameters
3. Note authentication requirements (public vs. authenticated vs. admin)

**CLI Tool** (`type: "cli"`):
1. Find the CLI entry point (main function, argument parser)
2. List all commands, subcommands, and arguments that accept user input
3. Trace which code paths are reachable from each argument

**Service** (`type: "service"`):
1. Find the network binding code (`grpc.server().add_insecure_port()`, `socket.bind()`, etc.)
2. Identify the protocol and exposed methods/endpoints
3. Document the wire format (gRPC proto, custom binary, JSON over TCP, etc.)

---

## Output Schema

> Must align with `agents/analyzer/AGENT.md §workspace/target.json Schema`.

```json
{
  "project_name": "example-project",
  "project_type": "webapp|service|cli|library",
  "network_exploitable": true,
  "valid_vuln_types": ["rce", "ssrf", "insecure_deserialization", "arbitrary_file_rw", "dos", "command_injection"],
  "version": "1.2.3",
  "language": "python",
  "framework": "flask",
  "repo_url": "https://github.com/owner/repo",
  "dependencies": ["flask", "requests"],
  "attack_surface": "Description of the attack surface",
  "entry_points": [
    {
      "type": "library_api|webapp_endpoint|cli_command|service_method",
      "path": "module.function()|POST /api/exec|tool --input|grpc.Method",
      "access_level": "none|auth|admin|local",
      "parameters": ["param1", "param2"],
      "source_file": "app/views.py:42"
    }
  ]
}
```

**Required fields**: `project_name`, `language`, `project_type`, `network_exploitable`, `valid_vuln_types`, `entry_points`.

**Field naming**: Use `project_name` (not `name`), `project_type` (not `type` at top level — `type` is reserved for entry point objects).

### Entry Point Fields

| Field | Description |
|-------|-------------|
| `type` | One of: `library_api`, `webapp_endpoint`, `cli_command`, `service_method` |
| `path` | How to invoke: function signature, HTTP endpoint, or CLI syntax |
| `access_level` | `none` (no auth), `auth` (requires login/token), `admin` (requires admin), `local` (requires code on same host) |
| `parameters` | User-controllable parameters at this entry point |
| `source_file` | Source file and line where this entry point is defined in original repo |

---

## Target Selection Guidance

> These are recommendations for the human operator selecting scan targets. Include in the `attack_surface` field if target is low-value.

### High-Value Targets (recommend scanning)

These targets have their own network attack surface and yield genuine remote vulnerabilities:

| Category | Examples |
|----------|---------|
| ML serving infrastructure | Triton Inference Server, Seldon Core, BentoML (server mode), Ray Serve, KServe, TorchServe |
| Data pipeline orchestrators | Apache Airflow, Prefect, Dagster, MLflow tracking server, Kubeflow Pipelines |
| LLM serving stacks | vLLM, text-generation-inference, LocalAI, Ollama, OpenLLM, llama.cpp server |
| Web frameworks & APIs | Any Flask/FastAPI/Django/Express application (not the framework itself) |
| Data infrastructure | Elasticsearch, Redis, distributed systems with network APIs |
| ML experiment trackers | MLflow, Weights & Biases server, ClearML server, Neptune server |
| Distributed ML | Horovod rendezvous server, NCCL bootstrap, PyTorch RPC, Spark REST API |

### Low-Value Targets (avoid — or adjust scope)

These targets are pure libraries; network-exploitable vulnerabilities are rare:

| Category | Examples | Why low-value |
|----------|---------|--------------|
| Data processing libraries | pandas, numpy, scipy, scikit-learn | No HTTP server; exploitation requires calling app |
| HTTP client libraries | requests, urllib3, httpx, aiohttp | They ARE the HTTP client, not a server |
| ML training libraries | PyTorch, TensorFlow, Keras, Chainer, MXNet | No server; model training is local |
| Serialization libraries | pickle, dill, joblib, cloudpickle | Local file loading, not network receiving |
| NLP/tokenizer libraries | tokenizers, spaCy, NLTK, gensim | No server |
| Database ORMs/drivers | SQLAlchemy, psycopg2, PyMySQL | They are clients, not servers |
| Data format libraries | h5py, PyTables, arrow | Local file processing |
| AWS/cloud SDKs | boto3, botocore, azure-sdk | Client SDKs only |

**If forced to scan a low-value target**: Restrict to `valid_vuln_types: ["dos", "command_injection"]` and note the limitation in `attack_surface`. Do NOT create HTTP wrappers.

---

## Best Practices

- Always use `--depth 1` to avoid pulling full history
- Check for existing Dockerfiles in the repo — they indicate the intended runtime
- Look for `.env.example` files to understand required environment variables
- Prefer release tags over HEAD for version identification
- **Entry points define the attack surface** — be thorough in discovery. Missing an entry point may cause valid vulnerabilities to be excluded
- For libraries, check `__init__.py` / `index.js` / package root exports to determine public API boundary
- **Never add entry points that don't exist in the original source** — if no HTTP routes exist, do not add them
