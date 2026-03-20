# Node.js / TypeScript Project Setup

Used when the project has no Docker Compose / Dockerfile and is identified as a Node.js or TypeScript project.

Prerequisite: `helpers/port-isolation.md`.
Databases have already been started by `db/*.md`.

> **MANDATORY (vuln-analysis)**: In vulnerability analysis mode, all execution must be done inside Docker containers. Generate a Dockerfile first, then proceed with subsequent steps.

---

## Detect Project Type

```bash
cd "$PROJECT_DIR"

# Detect TypeScript
IS_TYPESCRIPT=false
[ -f tsconfig.json ] && IS_TYPESCRIPT=true
grep -q '"typescript"' package.json 2>/dev/null && IS_TYPESCRIPT=true

# Detect package manager
PKG_MANAGER="npm"
[ -f yarn.lock ]       && PKG_MANAGER="yarn"
[ -f pnpm-lock.yaml ]  && PKG_MANAGER="pnpm"

# Detect framework
FRAMEWORK="unknown"
grep -q '"express"'  package.json 2>/dev/null && FRAMEWORK="express"
grep -q '"fastify"'  package.json 2>/dev/null && FRAMEWORK="fastify"
grep -q '"koa"'      package.json 2>/dev/null && FRAMEWORK="koa"
grep -q '"hapi"'     package.json 2>/dev/null && FRAMEWORK="hapi"
grep -q '"nest"'     package.json 2>/dev/null && FRAMEWORK="nestjs"
grep -q '"next"'     package.json 2>/dev/null && FRAMEWORK="nextjs"

# Detect Node version requirement
NODE_VERSION=$(node -e "try{const e=require('./package.json').engines?.node||'';console.log(e.replace(/[^0-9.]/g,'').split('.')[0]||'20')}catch(e){console.log('20')}" 2>/dev/null)
NODE_VERSION=${NODE_VERSION:-20}

# Detect port
APP_PORT=$(grep -rE "listen\(([0-9]{3,5})|PORT.*=.*([0-9]{3,5})" \
    $(find . -name "*.js" -o -name "*.ts" | grep -v node_modules | grep -v dist | head -20) 2>/dev/null \
    | grep -oE '[0-9]{3,5}' | grep -v '^3$\|^30$' | head -1)
APP_PORT=${APP_PORT:-3000}

echo "TypeScript: $IS_TYPESCRIPT | Framework: $FRAMEWORK | Port: $APP_PORT | Node: $NODE_VERSION"
```

---

## Dockerfile Template (JavaScript — Single Stage)

Used when `IS_TYPESCRIPT=false`:

```dockerfile
FROM node:<node_version>-slim
WORKDIR /app

# Install dependencies (production only)
COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE <port>
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD node -e "require('http').get('http://localhost:<port>/health',r=>process.exit(r.statusCode<400?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "app.js"]
```

---

## Dockerfile Template (TypeScript — Multi-stage Build)

Used when `IS_TYPESCRIPT=true`:

```dockerfile
# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM node:<node_version>-slim AS builder
WORKDIR /build

COPY package*.json tsconfig*.json ./
RUN npm ci

COPY src/ ./src/
# Copy other TS directories if they exist
COPY . .

RUN npm run build

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM node:<node_version>-slim
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /build/dist ./dist

EXPOSE <port>
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD node -e "require('http').get('http://localhost:<port>/health',r=>process.exit(r.statusCode<400?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "dist/index.js"]
```

### Variable Substitution

| Placeholder | Replace With |
|--------|--------|
| `<node_version>` | `NODE_VERSION` (e.g. `20`, minimum `18`) |
| `<port>` | Detected port (default `3000`) |

---

## Build Failure Handling

```bash
# Peer dependency conflicts
RUN npm install --legacy-peer-deps

# Network timeout — use mirror
RUN npm config set registry https://registry.npmmirror.com && npm ci

# node-gyp build failure (native modules)
RUN apt-get update && apt-get install -y build-essential python3 && npm ci

# TypeScript compilation failure — check tsconfig
# Common issues: outDir path mismatch, missing @types packages
# Check the actual command in the "build" script in package.json:
#   "build": "tsc" → dist/
#   "build": "tsc -p tsconfig.build.json" → uses specific config
#   "build": "nest build" → NestJS → dist/main.js

# NestJS special handling
FROM node:20-slim AS builder
RUN npm ci && npx nest build
# CMD ["node", "dist/main.js"]
```

---

## Environment Variables

```bash
if [ -f .env.example ] && [ ! -f .env ]; then
    cp .env.example .env
fi
```

Inject in Dockerfile:

```dockerfile
ENV NODE_ENV=production
ENV PORT=<port>
```

---

## Database Migration (Inside Dockerfile)

```dockerfile
# Prisma
RUN npx prisma generate
CMD ["sh", "-c", "npx prisma migrate deploy && node dist/index.js"]

# TypeORM
CMD ["sh", "-c", "node dist/migrate.js && node dist/main.js"]
```

---

## Cleanup

```bash
docker-compose down -v
docker rmi vuln-<pipeline_id>-target 2>/dev/null
```
