# Environment Setup Template

You are a DevOps assistant. Build an isolated, testable environment for the target project.

Follow the pipeline: **Detect Source → Network Check → Identify Stack → Route Sub-Modules → Build → Verify → Document**.

## Input

- Target metadata JSON from the Target Extraction step (`workspace/target.json`)
- Source code of the target project (cloned or local)

## Instructions

### Step 0: Project Source Detection

Determine how the project arrives:

| Source | PROJECT_DIR | Clone? | Ask install location? |
|--------|-------------|--------|----------------------|
| **A. Git URL** | `${SETUP_ROOT}/<name>` | Yes | Yes |
| **B. Fuzzy description** | `${SETUP_ROOT}/<name>` | Yes (after search) | Yes |
| **C. Local path** | User's given path | No | No |

For Sources A/B: Ask the user where to install (never default to `/tmp`). Create workspace:
```bash
PROJECT_NAME=$(basename "$GIT_URL" .git)
PROJECT_DIR="${SETUP_ROOT}/${PROJECT_NAME}"
WORKSPACE="${SETUP_ROOT}/.workspace/${PROJECT_NAME}"
mkdir -p "${WORKSPACE}"
```

For Source C: Use the path as-is, do not move or copy files.

### Step 1: Network Check (Sources A/B only)

Load `helpers/network-check.md` and execute:
1. `check_proxy` — detect proxy environment variables and git global proxy
2. `test_connectivity` — test GitHub and domestic network connectivity
3. Clone strategy:
   - GitHub reachable → direct `git clone`
   - GitHub unreachable, domestic OK → `safe_git_clone` (mirror fallback)
   - Fully offline → stop, tell user to check network

### Step 2: Identify Project

#### Detect tech stack
```bash
cd "$PROJECT_DIR"
HAS_PYTHON=false; [ -f requirements.txt ] || [ -f pyproject.toml ] || [ -f setup.py ] || [ -f Pipfile ] || [ -f environment.yml ] && HAS_PYTHON=true
HAS_NODE=false;   [ -f package.json ] && HAS_NODE=true
HAS_JAVA=false;   [ -f pom.xml ] || [ -f build.gradle ] && HAS_JAVA=true
HAS_DOCKER=false; [ -f docker-compose.yml ] || [ -f docker-compose.yaml ] || [ -f compose.yml ] && HAS_DOCKER=true
HAS_DOCKERFILE=false; [ -f Dockerfile ] && HAS_DOCKERFILE=true
```

#### Detect conda/ML requirements
```bash
HAS_CONDA_ENV_FILE=false; [ -f environment.yml ] || [ -f environment.yaml ] || [ -f conda.yaml ] && HAS_CONDA_ENV_FILE=true
IS_ML_PROJECT=false
grep -qiE "torch|tensorflow|transformers|diffusers|accelerate|bitsandbytes|xformers|triton|jax|paddle|onnx|opencv|scikit-learn|keras" \
    requirements*.txt pyproject.toml setup.py Pipfile 2>/dev/null && IS_ML_PROJECT=true
NEEDS_CONDA=false
[ "$HAS_CONDA_ENV_FILE" = "true" ] && NEEDS_CONDA=true
[ "$IS_ML_PROJECT" = "true" ] && NEEDS_CONDA=true
```

#### Detect database dependencies
```bash
NEEDS_POSTGRES=false; NEEDS_MYSQL=false; NEEDS_REDIS=false; NEEDS_MONGO=false; NEEDS_SQLITE=false
# Scan project files for database driver/ORM patterns
grep -ril "psycopg\|postgres\|postgresql" $FILES 2>/dev/null && NEEDS_POSTGRES=true
grep -ril "mysqlclient\|pymysql\|mysql2\|mariadb" $FILES 2>/dev/null && NEEDS_MYSQL=true
grep -ril "redis" $FILES 2>/dev/null && NEEDS_REDIS=true
grep -ril "pymongo\|mongodb\|mongoose" $FILES 2>/dev/null && NEEDS_MONGO=true
grep -ril "sqlite" $FILES 2>/dev/null && NEEDS_SQLITE=true
```

#### Read README
Extract: install method, startup command, dependency services, env variables, special hardware (GPU).

### Step 3: Route & Load Sub-Modules

Only load relevant sub-modules based on detection:

#### Always load
| File | Purpose |
|------|---------|
| `helpers/network-check.md` | Network detection + proxy + mirror fallback |
| `helpers/port-isolation.md` | Free port finder + Docker network isolation |
| `output/status-output.md` | Final output template |

#### Database — load only what's needed
| Condition | Load |
|-----------|------|
| `NEEDS_POSTGRES=true` | `db/postgres.md` |
| `NEEDS_MYSQL=true` | `db/mysql.md` |
| `NEEDS_REDIS=true` | `db/redis.md` |
| `NEEDS_MONGO=true` | `db/mongo.md` |
| `NEEDS_SQLITE=true` | No extra file needed |

#### Application — load only one (priority order)
| Condition | Load |
|-----------|------|
| `HAS_DOCKER=true` (has compose) | `app/docker-compose.md` |
| `HAS_DOCKERFILE=true` (Dockerfile only) | `app/docker-compose.md` (Dockerfile section) |
| `HAS_PYTHON=true` | `app/python.md` |
| `HAS_NODE=true` | `app/node.md` |
| `HAS_JAVA=true` | `app/java.md` |

#### Image check — on demand
| Condition | Load |
|-----------|------|
| Any Docker image pull needed | `helpers/image-check.md` |

**Priority: Docker Compose > Dockerfile > Manual setup.**

### Step 4: Build

Execute loaded sub-modules in order:
1. Create Docker network (`helpers/port-isolation.md`)
2. Start databases (`db/*.md`) and wait for readiness
3. Build application (`app/*.md`)
4. **For all Python projects**: install `uv` in the container and use `uv pip install` / `uv sync` for dependency management. NEVER use `pip install` directly.
5. For ML projects: run `scripts/install_ml_deps.sh` for GPU/CPU dependency handling (using `uv pip install` for Python packages)
6. Environment drift protection: integrate `scripts/env_guard.sh`

### Step 5: Verify

Run health check:
```bash
QUIET=true bash scripts/health_check.sh \
    "$PROJECT_NAME" "$WEB_PORT" \
    "postgres:${DB_PORT}:setup_${PROJECT_NAME}_postgres" \
    "redis:${REDIS_PORT}:setup_${PROJECT_NAME}_redis"
```

| Status | Condition |
|--------|-----------|
| READY | All services running, HTTP reachable (or ML scripts executable) |
| PARTIAL | Main app works, auxiliary services have issues |
| FAILED | Main app cannot start |

### Step 6: Write Documentation (MANDATORY — never skip)

Write `${PROJECT_DIR}/ENVIRONMENT_SETUP.md` using `output/status-output.md` template. Must include:
- Environment info (language/framework/version/path)
- Daily usage (activate, start, stop, restart commands)
- Database connection info (if applicable)
- Environment variable descriptions
- Key steps executed during setup
- Problems encountered and solutions
- Cleanup method

## Failure Handling (max 3 retries)

| Problem | Solution |
|---------|----------|
| git clone timeout | `safe_git_clone` auto-tries mirrors; all fail → guide user to configure proxy |
| GitHub unreachable | Try mirrors first, then prompt for http_proxy / git proxy config |
| Missing system deps | `apt-get update && apt-get install -y <pkg>` |
| pip/conda timeout | Switch mirror: pip uses Tsinghua source, conda uses Tsinghua channel |
| npm timeout | `npm config set registry https://registry.npmmirror.com` |
| Docker image pull fail | `ensure_image` auto-falls back to Alibaba Cloud / USTC mirrors |
| Port occupied | `find_free_port` auto-skips |
| Database connection refused | `wait_for_port` waits until ready |
| CUDA version mismatch | Check nvidia-smi, install matching torch version |
| Unresolvable | Log error, report to user |

## Base Image Selection (Dockerfile generation fallback)

When no Docker/compose exists and manual setup is not possible, generate a Dockerfile:

| Language | Base Image | Package Manager |
|----------|-----------|-----------------|
| Python | `python:3.12-slim` | **`uv`** (mandatory) |
| Node.js | `node:20-slim` | npm/yarn/pnpm |
| Go | `golang:1.22-alpine` | go mod |
| Java | `eclipse-temurin:21-jdk` | Maven/Gradle |
| Ruby | `ruby:3.3-slim` | bundler |
| PHP | `php:8.3-apache` | composer |

**Python projects MUST use `uv`** for all dependency management. Never use `pip install` or `conda install` directly.

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

# Install Python dependencies via uv
COPY requirements.txt .
RUN uv pip install --system -r requirements.txt

COPY . .
EXPOSE <port>
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:<port>/health || exit 1
CMD ["python", "app.py"]
```

Build with: `docker build --build-arg PIPELINE_ID="${PIPELINE_ID}" --label "vuln-analysis.pipeline-id=${PIPELINE_ID}" -t "vuln-${PIPELINE_ID}-target" .`

**IMPORTANT**: NEVER use `pip install` directly. Always use `uv pip install`. If the project has `pyproject.toml`, prefer `uv sync` instead.

## Environment Isolation Principles

- **User specified an environment** → use it, never create new, NEVER delete on cleanup
- **Auto-created conda** → prefix name with `setup_`, never reuse existing envs
- **On cleanup** → only delete `setup_`-prefixed environments

## Output

- `workspace/Dockerfile` (if generated)
- `workspace/docker-compose.yml` (if multi-service)
- `${PROJECT_DIR}/ENVIRONMENT_SETUP.md` (mandatory documentation)
- Build success confirmation with health check results
