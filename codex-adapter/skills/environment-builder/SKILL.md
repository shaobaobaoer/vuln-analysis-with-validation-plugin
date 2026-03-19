---
name: environment-builder
description: >
  Build Docker environments for vulnerability testing targets. Auto-detect tech stack,
  route to sub-modules (Docker Compose / Python / Node+TypeScript / Java / Go), provision
  databases, verify health, and generate setup documentation. Generates Dockerfiles for all
  4 target languages: Python (uv), Node.js/TypeScript (multi-stage), Java (Maven/Gradle
  multi-stage), Go (alpine multi-stage). Docker-first — all execution inside containers.
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
HAS_GO=false;     [ -f go.mod ] && HAS_GO=true
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
| `HAS_NODE=true` | `app/node.md` (covers both JavaScript and TypeScript) |
| `HAS_JAVA=true` | `app/java.md` |
| `HAS_GO=true` | `app/go.md` |

### Image check — on demand

| Condition | Load |
|-----------|------|
| Any Docker image pull needed | `helpers/image-check.md` |

**Priority: Docker Compose > Dockerfile > Manual setup.** When compose exists, use it directly — no need to read language-specific manual setup files.

---

## Test Harness Integrity (MANDATORY — Anti-Cheat Rule)

> **Safety Invariant #9**: The environment builder MUST NOT add insecure code patterns to the test harness that do not exist in the original repository.

When generating a test harness (e.g., a Flask wrapper for a library target), every HTTP endpoint MUST:
- Call only functions/classes that exist in the original target source code
- NOT introduce `exec()`, `eval()`, `pickle.loads()`, `subprocess.run(shell=True)`, or similar dangerous patterns unless they already exist in the target

**Before writing any test harness file, verify**:
```
For each endpoint in the harness:
  Does this call a function from the original cloned repo? → YES: allowed
  Does this add new insecure behavior not in the original? → YES: FORBIDDEN — remove it
```

Violations manufacture fake vulnerabilities and invalidate the entire pipeline run.

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

## Step 3a: Language-Specific Dockerfile Templates

When no Dockerfile or docker-compose.yml exists, generate one from the templates below based on detected language. Select the template that matches `HAS_JAVA`, `HAS_NODE`, `HAS_PYTHON`, or Go detection, then customize based on the project's actual build files.

### Template: Java (Maven)

```dockerfile
# Stage 1: Build
FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B       # cache deps first
COPY src ./src
RUN mvn package -DskipTests -B

# Stage 2: Run
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=5 \
    CMD curl -sf http://localhost:8080/ || exit 1
ENTRYPOINT ["java", "-jar", "app.jar"]
```

> **Log4j note**: If the target uses Log4j2 versions 2.0-beta9 to 2.14.1 (detectable in pom.xml), do NOT apply mitigations — keep vulnerable version intact for testing. Add comment in Dockerfile: `# Log4j version kept at vulnerable level for security testing`.

### Template: Java (Gradle)

```dockerfile
FROM gradle:8.5-jdk21 AS builder
WORKDIR /app
COPY build.gradle settings.gradle ./
COPY gradle ./gradle
RUN gradle dependencies --no-daemon    # cache deps
COPY src ./src
RUN gradle bootJar --no-daemon -x test

FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar app.jar
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=5 \
    CMD curl -sf http://localhost:8080/ || exit 1
ENTRYPOINT ["java", "-jar", "app.jar"]
```

### Template: Python (uv-based — MANDATORY for all Python projects)

```dockerfile
FROM python:3.12-slim
WORKDIR /app

# Install uv (NEVER use pip directly for deps)
RUN pip install --no-cache-dir uv

COPY requirements*.txt pyproject.toml ./  2>/dev/null || true
COPY . .

# Install with uv
RUN uv pip install --system -r requirements.txt 2>/dev/null || uv sync

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -sf http://localhost:8080/ || exit 1

CMD ["python", "app.py"]  # adjust to actual entry point
```

> **Note**: If `pyproject.toml` exists, prefer `uv sync` over `uv pip install -r requirements.txt`. If the project uses Flask: `CMD ["flask", "run", "--host=0.0.0.0", "--port=8080"]`. If FastAPI: `CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]`.

### Template: Node.js / TypeScript

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev          # install production deps only initially

# For TypeScript: install all deps for build step
COPY tsconfig*.json ./
RUN npm ci 2>/dev/null || npm install
COPY . .
RUN npm run build 2>/dev/null || true   # skip if no build script

# Production stage
FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist   2>/dev/null || true
COPY --from=builder /app/src ./src     2>/dev/null || true
COPY --from=builder /app/package*.json ./

EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=5 \
    CMD wget -qO- http://localhost:3000/ || exit 1

CMD ["node", "dist/index.js"]   # adjust: node src/index.js, npm start, etc.
```

> **For Express apps**: entry point is typically `node src/app.js` or `npm start`. For NestJS: `node dist/main.js`. For Next.js: `npm run start` after build.

### Template: Go

```dockerfile
# Stage 1: Build
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download                     # cache deps
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server  # adjust path

# Stage 2: Run (minimal image)
FROM alpine:3.19
RUN apk --no-cache add ca-certificates curl
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 \
    CMD curl -sf http://localhost:8080/health || exit 1
ENTRYPOINT ["./server"]
```

> **Go build path detection**: Look for `main.go` in `cmd/<name>/`, `cmd/`, or project root. Use `go build -o server .` if main is in root. Check `go.mod` for module name.

### Template: Ruby (Sinatra / Rails)

```dockerfile
FROM ruby:3.3-slim
RUN apt-get update && apt-get install -y build-essential curl libpq-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install --jobs 4 --without development test
COPY . .
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -sf http://localhost:3000/ || exit 1
CMD ["bundle", "exec", "ruby", "app.rb", "-p", "3000", "-o", "0.0.0.0"]
# For Rails: CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0", "-p", "3000"]
```

### Template: PHP (Laravel / Symfony)

```dockerfile
FROM php:8.3-apache
RUN apt-get update && apt-get install -y zip unzip curl && rm -rf /var/lib/apt/lists/*
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
WORKDIR /var/www/html
COPY . .
RUN composer install --no-dev --optimize-autoloader --no-interaction
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -sf http://localhost/ || exit 1
```

### Dockerfile Universal Requirements

Regardless of language, every generated Dockerfile MUST:
1. **Include `HEALTHCHECK`** — required for Docker readiness gate (Step 3)
2. **Label the image** — pass `--label "vuln-analysis.pipeline-id=${PIPELINE_ID}"` during `docker build`
3. **Expose the correct port** — match what the app listens on (detect from env vars, config files, README)
4. **NOT patch vulnerabilities** — if a target has a known vulnerable dependency, keep it! The goal is reproducible exploitation, not hardening
5. **Use multi-stage builds for compiled languages** — Java, Go: keeps final image small and runnable

---

## Step 3b: SQL Injection Testing Setup (only when `sql_injection` in `valid_vuln_types`)

When the vulnerability scanner will test for SQL injection, the database must have **realistic schema and seed data** before PoC execution. An empty database makes boolean-based and time-based blind SQLi much harder to distinguish from normal errors.

### 3b-1 — Detect App Schema

First, check if the app creates its own schema:
```bash
# Look for migration files or schema creation scripts
find "$PROJECT_DIR" -name "*.sql" -o -name "migrations/" -o -name "schema.py" \
    -o -name "models.py" -o -name "init_db*" 2>/dev/null | head -10
```

- **If migrations exist**: Run them normally (`flask db upgrade`, `alembic upgrade head`, `manage.py migrate`). The app's own schema is always preferred over synthetic seeding.
- **If no schema exists**: Seed a minimal schema (see §3b-2 below).

### 3b-2 — Minimal Seed Schema (when app provides no schema)

For Postgres/MySQL targets, inject a minimal schema after database readiness:

```sql
-- Seed for SQLi testing: realistic user + session tables
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(255) UNIQUE,
    expires_at TIMESTAMP
);

INSERT INTO users (username, password_hash, email, role) VALUES
    ('admin', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', 'admin@example.com', 'admin'),
    ('alice', '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', 'alice@example.com', 'user'),
    ('bob',   '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'bob@example.com', 'user')
ON CONFLICT (username) DO NOTHING;
```

Run via:
```bash
# Postgres
docker exec ${DB_CONTAINER} psql -U postgres -d ${DB_NAME} -f /tmp/seed.sql
# MySQL
docker exec ${DB_CONTAINER} mysql -u root -p${DB_PASS} ${DB_NAME} < seed.sql
```

### 3b-3 — Verify DB is Reachable from App

Before passing control to the vulnerability scanner, confirm the app actively queries the database:

```bash
# Check DB logs show incoming connections from the app container
docker logs ${DB_CONTAINER} 2>&1 | tail -20 | grep -i "connection\|query\|accept" || true

# Verify the app returns DB-backed data (not hardcoded or in-memory)
curl -s "http://localhost:${WEB_PORT}/" | head -5
```

> **If the app doesn't connect to the DB at all**: Set `NEEDS_SQLITE=true` if it uses an embedded DB, or note in `ENVIRONMENT_SETUP.md` that the DB connection is optional/disabled — this limits SQLi testing scope.

### 3b-4 — Document in ENVIRONMENT_SETUP.md

Add a `## SQL Injection Testing Notes` section to `workspace/ENVIRONMENT_SETUP.md`:

```markdown
## SQL Injection Testing Notes
- DB backend: <postgres|mysql|sqlite>
- Schema source: <app migrations|synthetic seed>
- Tables available: users, sessions (+ app-specific tables if any)
- Connection string: postgresql://postgres@localhost:<port>/<db_name>
- Test credentials: admin / (hash in users table)
```

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
