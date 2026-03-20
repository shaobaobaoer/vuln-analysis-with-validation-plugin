# Go 项目搭建

当项目没有 Docker Compose / Dockerfile，且识别为 Go 项目时使用。

前置依赖：`helpers/port-isolation.md`。
数据库已由 `db/*.md` 启动完毕。

> **MANDATORY**: 所有 Go 项目必须使用 Docker 容器运行。禁止在宿主机直接运行 `go run` 或编译好的二进制文件执行测试。

---

## 检测构建信息

```bash
cd "$PROJECT_DIR"

# 读取模块名
MODULE_NAME=$(grep "^module " go.mod | awk '{print $2}')
GO_VERSION=$(grep "^go " go.mod | awk '{print $2}')

echo "Module: $MODULE_NAME"
echo "Go version: $GO_VERSION"

# 查找主入口
MAIN_FILE=$(find . -name "main.go" | grep -v vendor | head -3)
echo "Main files: $MAIN_FILE"

# 检测框架
FRAMEWORK="stdlib"
grep -q "gin-gonic/gin" go.mod   && FRAMEWORK="gin"
grep -q "labstack/echo"  go.mod  && FRAMEWORK="echo"
grep -q "gorilla/mux"    go.mod  && FRAMEWORK="gorilla"
grep -q "go-chi/chi"     go.mod  && FRAMEWORK="chi"
grep -q "beego"          go.mod  && FRAMEWORK="beego"
echo "Framework: $FRAMEWORK"

# 检测默认端口
APP_PORT=$(grep -rE 'Listen\(.*:([0-9]+)|:([0-9]{4,5})' \
    $(find . -name "*.go" | grep -v vendor | head -20) 2>/dev/null \
    | grep -oE '[0-9]{4,5}' | head -1)
APP_PORT=${APP_PORT:-8080}
```

---

## Dockerfile 模板（Go multi-stage build）

```dockerfile
# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM golang:<go_version>-alpine AS builder

# 安装 git（私有模块依赖时需要）
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# 缓存 go.mod / go.sum（依赖层单独缓存）
COPY go.mod go.sum ./
RUN go mod download

# 复制源码并编译
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

### 变量替换

| 占位符 | 替换为 |
|--------|--------|
| `<go_version>` | `go.mod` 中的 Go 版本（如 `1.22`）；若 < 1.18 使用 `1.22` |
| `<port>` | 检测到的端口（默认 `8080`） |

---

## 编译失败处理

```bash
# 1. 依赖下载失败（网络问题）
RUN GOPROXY=https://goproxy.cn,direct go mod download

# 2. CGO 依赖（sqlite3 / librdkafka 等）— 改用带 gcc 的镜像
FROM golang:<go_version> AS builder   # 不用 alpine，改用 debian-based

# 3. 私有模块
RUN git config --global url."https://token@github.com/".insteadOf "https://github.com/"

# 4. 找不到 main 包（monorepo / 多模块）
# 修改 go build 目标为子目录
RUN go build -o /app/server ./cmd/server/
# 或
RUN go build -o /app/server ./cmd/api/

# 5. 依赖 CGO 且必须 alpine — 安装 musl-libc
RUN apk add --no-cache gcc musl-dev
RUN CGO_ENABLED=1 go build -o /app/server .
```

---

## Docker Compose 模板

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
      # 注入数据库连接（若有）
      - DATABASE_URL=${DATABASE_URL:-}
      - REDIS_URL=${REDIS_URL:-}
    depends_on:
      db:
        condition: service_healthy   # 若有数据库
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:<container_port>/health"]
      interval: 5s
      timeout: 3s
      retries: 10
    restart: unless-stopped
```

---

## 健康检查替代方案

Go 应用若无 `/health` 端点，使用 TCP 检查：

```dockerfile
# TCP 端口探活（不依赖 HTTP 路由）
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
    CMD nc -z localhost <port> || exit 1
```

安装 netcat：

```dockerfile
RUN apk add --no-cache ca-certificates curl netcat-openbsd
```

---

## 框架特定启动端口配置

| 框架 | 端口配置方式 |
|------|------------|
| Gin | `router.Run(":PORT")` 或 `PORT` 环境变量 |
| Echo | `e.Start(":PORT")` |
| Chi / stdlib | `http.ListenAndServe(":PORT", ...)` |
| Beego | `beego.Run(":PORT")` 或 `app.conf` |

在 Dockerfile 中传入端口：

```dockerfile
ENV PORT=8080
CMD ["./server"]
```

---

## 清理

```bash
docker-compose down -v
docker rmi vuln-<pipeline_id>-target 2>/dev/null
```
