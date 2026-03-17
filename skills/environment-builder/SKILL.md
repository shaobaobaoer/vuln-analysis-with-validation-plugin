---
name: environment-builder
description: >
  Build isolated environments for vulnerability testing targets. Auto-detect tech stack,
  route to sub-modules (Docker Compose / Python / Node / Java), provision databases,
  verify health, and generate setup documentation. Supports conda, venv, and Docker.
origin: vuln-analysis
---

# Environment Builder

Turn a target project from source code into a running, testable environment.
Follow: **Detect Source -> Network Check -> Identify Stack -> Route -> Build -> Verify -> Document**.

**Key principle: Only load the sub-modules you need. Do not read unrelated files.**

---

## Project Source Detection

Three ways a target project arrives — each follows a different flow:

| Source | PROJECT_DIR | Clone? | Ask install location? |
|--------|-------------|--------|----------------------|
| **A. Git URL** | `${SETUP_ROOT}/<name>` | Yes | Yes |
| **B. Fuzzy description** | `${SETUP_ROOT}/<name>` | Yes (after search) | Yes |
| **C. Local path** | User's given path | No | No |

### Source A/B: Need to clone

**Ask the user first** where to install (do NOT default to `/tmp`):

1. Ask: "Where should the project be placed?"
2. User specifies -> use that
3. No preference -> suggest `~/projects/<project_name>`
4. User explicitly says temporary -> use `/tmp/setup/`

```bash
PROJECT_NAME=$(basename "$GIT_URL" .git)
PROJECT_DIR="${SETUP_ROOT}/${PROJECT_NAME}"
WORKSPACE="${SETUP_ROOT}/.workspace/${PROJECT_NAME}"
mkdir -p "${WORKSPACE}"
```

Then run **Step 0: Network Check** before cloning.

### Source C: Local project (install in-place)

```bash
PROJECT_DIR="/path/to/user/project"
PROJECT_NAME=$(basename "$PROJECT_DIR")
WORKSPACE="${PROJECT_DIR}/.workspace"
mkdir -p "${WORKSPACE}"
```

**Do not move or copy user files. Skip network check and clone, go directly to Step 1.**

---

## Step 0: Network Check (Sources A/B only, skip for local)

Read `helpers/network-check.md` and execute in order:

1. `check_proxy` — detect environment variables and git global proxy
2. `test_connectivity` — test GitHub and domestic network connectivity
3. Decide clone strategy:
   - GitHub reachable -> direct `git clone`
   - GitHub unreachable but domestic OK -> `safe_git_clone` (auto-tries mirrors)
   - Fully offline -> stop, tell user to check network

**Always use `safe_git_clone` for cloning** — it has built-in timeout detection, mirror fallback, and proxy guidance.

---

## Step 1: Identify Project

### Detect tech stack

```bash
cd "$PROJECT_DIR"

# Language/framework
HAS_PYTHON=false; [ -f requirements.txt ] || [ -f pyproject.toml ] || [ -f setup.py ] || [ -f Pipfile ] || [ -f environment.yml ] || [ -f conda.yaml ] && HAS_PYTHON=true
HAS_NODE=false;   [ -f package.json ] && HAS_NODE=true
HAS_JAVA=false;   [ -f pom.xml ] || [ -f build.gradle ] && HAS_JAVA=true
HAS_DOCKER=false; [ -f docker-compose.yml ] || [ -f docker-compose.yaml ] || [ -f compose.yml ] && HAS_DOCKER=true
HAS_DOCKERFILE=false; [ -f Dockerfile ] && HAS_DOCKERFILE=true

# Conda detection (only check command availability and project files, NOT existing envs)
HAS_CONDA_ENV_FILE=false; [ -f environment.yml ] || [ -f environment.yaml ] || [ -f conda.yaml ] && HAS_CONDA_ENV_FILE=true
CONDA_AVAILABLE=false; which conda >/dev/null 2>&1 && CONDA_AVAILABLE=true

# ML/AI project detection (determines if conda is needed)
IS_ML_PROJECT=false
grep -qiE "torch|tensorflow|transformers|diffusers|accelerate|bitsandbytes|xformers|triton|jax|paddle|onnx|opencv|scikit-learn|keras" \
    requirements*.txt pyproject.toml setup.py Pipfile 2>/dev/null && IS_ML_PROJECT=true

NEEDS_CONDA=false
[ "$HAS_CONDA_ENV_FILE" = "true" ] && NEEDS_CONDA=true
[ "$IS_ML_PROJECT" = "true" ] && NEEDS_CONDA=true
```

### Detect database dependencies

```bash
NEEDS_POSTGRES=false; NEEDS_MYSQL=false; NEEDS_REDIS=false; NEEDS_MONGO=false; NEEDS_SQLITE=false

FILES=$(find "$PROJECT_DIR" -maxdepth 3 \
    \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.yml" -o -name "*.yaml" \
       -o -name "*.env*" -o -name "*.cfg" -o -name "*.ini" -o -name "*.conf" \
       -o -name "requirements*.txt" -o -name "package.json" -o -name "Pipfile" \
       -o -name "pyproject.toml" -o -name "docker-compose*" \) 2>/dev/null)

grep -ril "psycopg\|postgres\|postgresql" $FILES 2>/dev/null && NEEDS_POSTGRES=true
grep -ril "mysqlclient\|pymysql\|mysql2\|mariadb" $FILES 2>/dev/null && NEEDS_MYSQL=true
grep -ril "redis" $FILES 2>/dev/null && NEEDS_REDIS=true
grep -ril "pymongo\|mongodb\|mongoose" $FILES 2>/dev/null && NEEDS_MONGO=true
grep -ril "sqlite" $FILES 2>/dev/null && NEEDS_SQLITE=true
```

### Read README

Extract: install method, startup command, dependency services, env variables, special hardware requirements (GPU).

---

## Step 2: Route & Load Sub-Modules

Based on detection results, **only read the relevant sub-module files**:

### Always read

| File | Purpose |
|------|---------|
| `helpers/network-check.md` | Network detection + proxy + mirror fallback (before clone) |
| `helpers/port-isolation.md` | Free port finder + Docker network isolation |
| `output/status-output.md` | Final output template |

### Database — load only what's needed

| Condition | Load |
|-----------|------|
| `NEEDS_POSTGRES=true` | `db/postgres.md` |
| `NEEDS_MYSQL=true` | `db/mysql.md` |
| `NEEDS_REDIS=true` | `db/redis.md` |
| `NEEDS_MONGO=true` | `db/mongo.md` |
| `NEEDS_SQLITE=true` | No extra file needed |

### Application — load only one

| Condition | Load |
|-----------|------|
| `HAS_DOCKER=true` (has compose) | `app/docker-compose.md` |
| `HAS_DOCKERFILE=true` (Dockerfile only) | `app/docker-compose.md` (reuse its Dockerfile section) |
| `HAS_PYTHON=true` | `app/python.md` |
| `HAS_NODE=true` | `app/node.md` |
| `HAS_JAVA=true` | `app/java.md` |

### Image check — on demand

| Condition | Load |
|-----------|------|
| Any Docker image pull needed | `helpers/image-check.md` |

**Priority: Docker Compose > Dockerfile > Manual setup.** When compose exists, use it directly — no need to read language-specific manual setup files.

---

## Step 3: Build

Execute loaded sub-modules in order:

1. Create Docker network (`helpers/port-isolation.md`)
2. Start databases (`db/*.md`)
3. Wait for databases to be ready
4. Build application (`app/*.md`)

**Python Dependency Management (MANDATORY for all Python projects)**:
- ALL generated Dockerfiles MUST use `uv` for dependency installation
- NEVER use `pip install`, `conda install`, or `python -m venv` in Dockerfiles
- Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Install deps: `uv pip install --system -r requirements.txt`
- If `pyproject.toml` exists: `uv sync`

**Docker Resource Labeling (MANDATORY)**:
- ALL `docker build` and `docker run` commands MUST include `--label "vuln-analysis.pipeline-id=${PIPELINE_ID}"`
- Docker Compose files MUST include `labels:` section in all services and networks

---

## Step 4: Verify

```bash
QUIET=true bash scripts/health_check.sh \
    "$PROJECT_NAME" "$WEB_PORT" \
    "postgres:${DB_PORT}:setup_${PROJECT_NAME}_postgres" \
    "redis:${REDIS_PORT}:setup_${PROJECT_NAME}_redis"

# SQLite-only projects
QUIET=true bash scripts/health_check.sh \
    "$PROJECT_NAME" "$WEB_PORT" sqlite
```

### Status criteria

| Status | Condition |
|--------|-----------|
| READY | All services running, HTTP reachable (or ML scripts executable) |
| PARTIAL | Main app works, auxiliary services have issues |
| FAILED | Main app cannot start |

---

## Step 5: Write Documentation (MANDATORY — never skip)

After build completes, **MUST** write full environment documentation to `workspace/ENVIRONMENT_SETUP.md` using the template from `output/status-output.md`.

> **vuln-analysis pipeline**: always write to `workspace/ENVIRONMENT_SETUP.md`, not to the cloned project source directory. Other pipeline artifacts (Dockerfile, docker-compose.yml, results.json) all live in `workspace/` — ENVIRONMENT_SETUP.md belongs there too.

This step cannot be skipped. After the user closes the terminal, this file is the only reference.

The document must include:
- Environment info (language/framework/version/path)
- Daily usage (activate, start, stop, restart commands)
- Database connection info (if applicable)
- Environment variable descriptions
- Key steps executed during setup
- Problems encountered and solutions
- Cleanup method

---

## Special Case: Project Already Running

Do not rebuild. Check ports and verify directly:

```bash
ss -tlnp | grep -E ":(3000|5000|8000|8080|8888) "
docker ps --format "table {{.Names}}\t{{.Ports}}" 2>/dev/null | grep -i setup
```

---

## Failure Handling (max 3 retries)

| Problem | Solution |
|---------|----------|
| git clone timeout | `safe_git_clone` auto-tries mirrors; all fail -> guide user to configure proxy |
| GitHub unreachable | Try mirrors first, then prompt for http_proxy / git proxy config |
| Missing system deps | `apt-get update && apt-get install -y <pkg>` |
| pip/conda timeout | Switch mirror: pip uses Tsinghua source, conda uses Tsinghua channel |
| npm timeout | `npm config set registry https://registry.npmmirror.com` |
| Docker image pull fail | `ensure_image` auto-falls back to Alibaba Cloud / USTC mirrors |
| Port occupied | `find_free_port` auto-skips |
| Database connection refused | `wait_for_port` waits until ready |
| CUDA version mismatch | Check nvidia-smi, install matching torch version |
| Unresolvable | Log error, report to user |

---

## Base Image Selection (Dockerfile generation fallback)

When no Docker/compose exists and manual setup is not possible, generate a Dockerfile:

| Language | Base Image |
|----------|-----------|
| Python | `python:3.12-slim` |
| Node.js | `node:20-slim` |
| Go | `golang:1.22-alpine` |
| Java | `eclipse-temurin:21-jdk` |
| Ruby | `ruby:3.3-slim` |
| PHP | `php:8.3-apache` |

### Dockerfile Template (Python — using `uv`)

```dockerfile
FROM python:3.12-slim
WORKDIR /app

# Pipeline label for safe cleanup (value injected via --build-arg or --label at build time)
ARG PIPELINE_ID="unknown"
LABEL vuln-analysis.pipeline-id="${PIPELINE_ID}"

# Install system deps + uv
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc && rm -rf /var/lib/apt/lists/* \
    && curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Install Python dependencies via uv (NEVER use pip directly)
COPY requirements.txt .
RUN uv pip install --system -r requirements.txt

COPY . .
EXPOSE <port>
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:<port>/health || exit 1
CMD ["python", "app.py"]
```

Build with: `docker build --build-arg PIPELINE_ID="${PIPELINE_ID}" --label "vuln-analysis.pipeline-id=${PIPELINE_ID}" -t "vuln-${PIPELINE_ID}-target" .`

**IMPORTANT**: Always use `uv pip install` instead of `pip install`. If the project has `pyproject.toml`, prefer `uv sync`.

### Dockerfile Best Practices

- **Always include HEALTHCHECK** — the Docker readiness gate (Step 3) cannot verify the app is running without it. Use `CMD curl -f http://localhost:<port>/health || exit 1`. If the app has no `/health` endpoint, probe a known-good path (e.g., `/`, `/api/v1/status`) or the CLI exit code.
- Use `--no-install-recommends` to keep images small
- Pin dependency versions where possible
- For multi-service projects (app + DB), always use docker-compose
- **Always label** all resources with `vuln-analysis.pipeline-id=${PIPELINE_ID}` — apply via `docker build --label` and `docker run --label` (the orchestrator provides `PIPELINE_ID`)

### Dockerfile Path Rules (Reproducibility)

Generated Dockerfiles MUST use relative or container-internal paths only. Hardcoded host-absolute paths break reproducibility when the workspace is moved or shared.

| Pattern | Status | Fix |
|---------|--------|-----|
| `COPY . .` | OK | Relative — always correct |
| `WORKDIR /app` | OK | Container-internal path |
| `COPY /Users/alice/project/file .` | **FORBIDDEN** | Use `COPY file .` |
| `COPY /home/user/workspace/poc.py .` | **FORBIDDEN** | Use build context or `ARG` |
| `RUN pip install /abs/path/to/package` | **FORBIDDEN** | Copy first, then install |

Use `ARG` for values that legitimately vary between builds (e.g., pipeline ID, port numbers):

```dockerfile
ARG PIPELINE_ID="unknown"
ARG APP_PORT=8080
LABEL vuln-analysis.pipeline-id="${PIPELINE_ID}"
EXPOSE ${APP_PORT}
HEALTHCHECK CMD curl -f http://localhost:${APP_PORT}/health || exit 1
```

---

## Environment Isolation Principles

- **User specified an environment** -> use it, never create new, **NEVER delete on cleanup**
- **Auto-created conda** -> prefix name with `setup_`, never reuse existing envs
- **On cleanup** -> only delete `setup_`-prefixed environments

---

## Output

- `workspace/Dockerfile` (if generated)
- `workspace/docker-compose.yml` (if multi-service)
- `workspace/ENVIRONMENT_SETUP.md` (mandatory documentation — always in workspace/)
- Build success confirmation with health check results

---

## Sub-Module Reference

```
skills/environment-builder/
├── SKILL.md                    # This file — main orchestration
├── app/
│   ├── python.md               # Python: conda/venv, ML deps, framework startup
│   ├── node.md                 # Node.js: npm/yarn/pnpm, migrations, startup
│   ├── java.md                 # Java: Maven/Gradle build, Spring Boot startup
│   └── docker-compose.md       # Docker Compose / Dockerfile workflows
├── db/
│   ├── postgres.md             # PostgreSQL container setup
│   ├── redis.md                # Redis container setup
│   ├── mysql.md                # MySQL container setup
│   └── mongo.md                # MongoDB container setup
├── helpers/
│   ├── network-check.md        # Proxy detection, connectivity test, mirror clone
│   ├── image-check.md          # Docker image pull with mirror fallback
│   └── port-isolation.md       # Free port finder, Docker network, wait_for_service
├── output/
│   └── status-output.md        # ENVIRONMENT_SETUP.md template
└── scripts/
    ├── health_check.sh         # Full health verification (web + db + resources)
    ├── setup_python_env.sh     # Create conda/venv + install deps
    ├── install_ml_deps.sh      # ML/AI GPU/CPU dependency installer
    ├── install_conda.sh        # Miniforge auto-installer
    └── env_guard.sh            # Environment drift detection & auto-recovery
```
