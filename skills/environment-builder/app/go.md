# Go Project Setup

Used when the project has no Docker Compose / Dockerfile and is identified as a Go project.

Prerequisite: `helpers/port-isolation.md`.
Databases have already been started by `db/*.md`.

> **MANDATORY**: All Go projects must run inside Docker containers. Running `go run` or compiled binaries directly on the host is prohibited.

---

## Detect Build Information

```bash
cd "$PROJECT_DIR"

# Read module name
MODULE_NAME=$(grep "^module " go.mod | awk '{print $2}')
GO_VERSION=$(grep "^go " go.mod | awk '{print $2}')

echo "Module: $MODULE_NAME"
echo "Go version: $GO_VERSION"

# Find main entry point
MAIN_FILE=$(find . -name "main.go" | grep -v vendor | head -3)
echo "Main files: $MAIN_FILE"

# Detect framework
FRAMEWORK="stdlib"
grep -q "gin-gonic/gin" go.mod   && FRAMEWORK="gin"
grep -q "labstack/echo"  go.mod  && FRAMEWORK="echo"
grep -q "gorilla/mux"    go.mod  && FRAMEWORK="gorilla"
grep -q "go-chi/chi"     go.mod  && FRAMEWORK="chi"
grep -q "beego"          go.mod  && FRAMEWORK="beego"
echo "Framework: $FRAMEWORK"

# Detect default port
APP_PORT=$(grep -rE 'Listen\(.*:([0-9]+)|:([0-9]{4,5})' \
    $(find . -name "*.go" | grep -v vendor | head -20) 2>/dev/null \
    | grep -oE '[0-9]{4,5}' | head -1)
APP_PORT=${APP_PORT:-8080}
```

---

## Dockerfile Template (Go multi-stage build)

```dockerfile
# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM golang:<go_version>-alpine AS builder

# Install git (needed for private module dependencies)
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache go.mod / go.sum (separate dependency layer cache)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and compile
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /app/server .

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates curl

WORKDIR /app
COPY --from=builder /app/server .

EXPOSE <port>
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:<port>/health || \
        curl -f http://localhost:<port>/ || exit 1

CMD ["./server"]
```

### Variable Substitution

| Placeholder | Replace With |
|--------|--------|
| `<go_version>` | Go version from `go.mod` (e.g. `1.22`); if < 1.18 use `1.22` |
| `<port>` | Detected port (default `8080`) |

---

## Build Failure Handling

```bash
# 1. Dependency download failure (network issue)
RUN GOPROXY=https://goproxy.cn,direct go mod download

# 2. CGO dependency (sqlite3 / librdkafka etc.) — switch to image with gcc
FROM golang:<go_version> AS builder   # Don't use alpine, use debian-based instead

# 3. Private modules
RUN git config --global url."https://token@github.com/".insteadOf "https://github.com/"

# 4. Cannot find main package (monorepo / multi-module)
# Change go build target to subdirectory
RUN go build -o /app/server ./cmd/server/
# Or
RUN go build -o /app/server ./cmd/api/

# 5. Requires CGO and must use alpine — install musl-libc
RUN apk add --no-cache gcc musl-dev
RUN CGO_ENABLED=1 go build -o /app/server .
```

---

## Docker Compose Template

```yaml
version: "3.8"
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "<host_port>:<container_port>"
    environment:
      - PORT=<container_port>
      # Inject database connection (if applicable)
      - DATABASE_URL=${DATABASE_URL:-}
      - REDIS_URL=${REDIS_URL:-}
    depends_on:
      db:
        condition: service_healthy   # If database exists
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:<container_port>/health"]
      interval: 5s
      timeout: 3s
      retries: 10
    restart: unless-stopped
```

---

## Health Check Alternative

If Go application has no `/health` endpoint, use TCP check:

```dockerfile
# TCP port probe (does not depend on HTTP routing)
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
    CMD nc -z localhost <port> || exit 1
```

Install netcat:

```dockerfile
RUN apk add --no-cache ca-certificates curl netcat-openbsd
```

---

## Framework-Specific Port Configuration

| Framework | Port Configuration Method |
|------|------------|
| Gin | `router.Run(":PORT")` or `PORT` env variable |
| Echo | `e.Start(":PORT")` |
| Chi / stdlib | `http.ListenAndServe(":PORT", ...)` |
| Beego | `beego.Run(":PORT")` or `app.conf` |

Pass port in Dockerfile:

```dockerfile
ENV PORT=8080
CMD ["./server"]
```

---

## Cleanup

```bash
docker-compose down -v
docker rmi vuln-<pipeline_id>-target 2>/dev/null
```
