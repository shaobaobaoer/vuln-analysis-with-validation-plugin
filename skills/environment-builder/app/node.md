# Node.js / TypeScript 项目搭建

当项目没有 Docker Compose / Dockerfile，且识别为 Node.js 或 TypeScript 项目时使用。

前置依赖：`helpers/port-isolation.md`。
数据库已由 `db/*.md` 启动完毕。

> **MANDATORY (vuln-analysis)**: 漏洞分析模式下，所有执行必须在 Docker 容器内进行。先生成 Dockerfile，再继续后续步骤。

---

## 检测项目类型

```bash
cd "$PROJECT_DIR"

# 检测 TypeScript
IS_TYPESCRIPT=false
[ -f tsconfig.json ] && IS_TYPESCRIPT=true
grep -q '"typescript"' package.json 2>/dev/null && IS_TYPESCRIPT=true

# 检测包管理器
PKG_MANAGER="npm"
[ -f yarn.lock ]       && PKG_MANAGER="yarn"
[ -f pnpm-lock.yaml ]  && PKG_MANAGER="pnpm"

# 检测框架
FRAMEWORK="unknown"
grep -q '"express"'  package.json 2>/dev/null && FRAMEWORK="express"
grep -q '"fastify"'  package.json 2>/dev/null && FRAMEWORK="fastify"
grep -q '"koa"'      package.json 2>/dev/null && FRAMEWORK="koa"
grep -q '"hapi"'     package.json 2>/dev/null && FRAMEWORK="hapi"
grep -q '"nest"'     package.json 2>/dev/null && FRAMEWORK="nestjs"
grep -q '"next"'     package.json 2>/dev/null && FRAMEWORK="nextjs"

# 检测 Node 版本要求
NODE_VERSION=$(node -e "try{const e=require('./package.json').engines?.node||'';console.log(e.replace(/[^0-9.]/g,'').split('.')[0]||'20')}catch(e){console.log('20')}" 2>/dev/null)
NODE_VERSION=${NODE_VERSION:-20}

# 检测端口
APP_PORT=$(grep -rE "listen\(([0-9]{3,5})|PORT.*=.*([0-9]{3,5})" \
    $(find . -name "*.js" -o -name "*.ts" | grep -v node_modules | grep -v dist | head -20) 2>/dev/null \
    | grep -oE '[0-9]{3,5}' | grep -v '^3$\|^30$' | head -1)
APP_PORT=${APP_PORT:-3000}

echo "TypeScript: $IS_TYPESCRIPT | Framework: $FRAMEWORK | Port: $APP_PORT | Node: $NODE_VERSION"
```

---

## Dockerfile 模板（JavaScript — 单阶段）

当 `IS_TYPESCRIPT=false` 时使用：

```dockerfile
FROM node:<node_version>-slim
WORKDIR /app

# 安装依赖（仅 production）
COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE <port>
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD node -e "require('http').get('http://localhost:<port>/health',r=>process.exit(r.statusCode<400?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "app.js"]
```

---

## Dockerfile 模板（TypeScript — 多阶段 build）

当 `IS_TYPESCRIPT=true` 时使用：

```dockerfile
# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM node:<node_version>-slim AS builder
WORKDIR /build

COPY package*.json tsconfig*.json ./
RUN npm ci

COPY src/ ./src/
# 若存在其他 TS 目录也复制进来
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

### 变量替换

| 占位符 | 替换为 |
|--------|--------|
| `<node_version>` | `NODE_VERSION`（如 `20`，最低 `18`） |
| `<port>` | 检测到的端口（默认 `3000`） |

---

## 编译失败处理

```bash
# peer 依赖冲突
RUN npm install --legacy-peer-deps

# 网络超时 — 使用镜像源
RUN npm config set registry https://registry.npmmirror.com && npm ci

# node-gyp 编译失败（native 模块）
RUN apt-get update && apt-get install -y build-essential python3 && npm ci

# TypeScript 编译失败 — 检查 tsconfig
# 常见问题：outDir 路径不匹配、缺少 @types 包
# 检查 package.json 中 "build" 脚本的实际命令：
#   "build": "tsc" → dist/
#   "build": "tsc -p tsconfig.build.json" → 使用特定配置
#   "build": "nest build" → NestJS → dist/main.js

# NestJS 特殊处理
FROM node:20-slim AS builder
RUN npm ci && npx nest build
# CMD ["node", "dist/main.js"]
```

---

## 环境变量

```bash
if [ -f .env.example ] && [ ! -f .env ]; then
    cp .env.example .env
fi
```

在 Dockerfile 中注入：

```dockerfile
ENV NODE_ENV=production
ENV PORT=<port>
```

---

## 数据库迁移（Dockerfile 内）

```dockerfile
# Prisma
RUN npx prisma generate
CMD ["sh", "-c", "npx prisma migrate deploy && node dist/index.js"]

# TypeORM
CMD ["sh", "-c", "node dist/migrate.js && node dist/main.js"]
```

---

## 清理

```bash
docker-compose down -v
docker rmi vuln-<pipeline_id>-target 2>/dev/null
```
