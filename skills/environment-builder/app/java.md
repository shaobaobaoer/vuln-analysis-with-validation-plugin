# Java 项目搭建

当项目没有 Docker Compose / Dockerfile，且识别为 Java 项目时使用。

前置依赖：`helpers/port-isolation.md`。
数据库已由 `db/*.md` 启动完毕。

> **MANDATORY (vuln-analysis)**: 漏洞分析模式下，所有执行必须在 Docker 容器内进行。先生成 Dockerfile，再继续后续步骤。

---

## Dockerfile 模板（Java multi-stage build）

### Maven 项目

```dockerfile
# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-<java_version> AS builder
WORKDIR /build

# 缓存依赖层
COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src/ ./src/
RUN mvn clean package -DskipTests -B

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM eclipse-temurin:<java_version>-jre-alpine
WORKDIR /app

COPY --from=builder /build/target/*.jar app.jar

EXPOSE <port>
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
    CMD wget -qO- http://localhost:<port>/actuator/health || \
        wget -qO- http://localhost:<port>/health || exit 1

CMD ["java", "-jar", "app.jar"]
```

### Gradle 项目

```dockerfile
# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM gradle:8.5-jdk<java_version> AS builder
WORKDIR /build

COPY build.gradle* settings.gradle* gradle.properties* ./
COPY gradle/ ./gradle/
RUN gradle dependencies --no-daemon 2>/dev/null || true

COPY src/ ./src/
RUN gradle bootJar --no-daemon -x test

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM eclipse-temurin:<java_version>-jre-alpine
WORKDIR /app

COPY --from=builder /build/build/libs/*.jar app.jar

EXPOSE <port>
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
    CMD wget -qO- http://localhost:<port>/actuator/health || \
        wget -qO- http://localhost:<port>/health || exit 1

CMD ["java", "-jar", "app.jar"]
```

### 变量替换

| 占位符 | 替换为 |
|--------|--------|
| `<java_version>` | `pom.xml` 中 `<java.version>` 或 `build.gradle` 中 `sourceCompatibility`（如 `17`、`21`）；默认 `17` |
| `<port>` | 检测到的 `server.port`（默认 `8080`） |

---

## 检测构建工具

```bash
cd "$PROJECT_DIR"

if [ -f pom.xml ]; then
    BUILD_TOOL="maven"
elif [ -f build.gradle ] || [ -f build.gradle.kts ]; then
    BUILD_TOOL="gradle"
else
    echo "❌ 未识别的 Java 构建工具"
fi
```

---

## 编译

```bash
if [ "$BUILD_TOOL" = "maven" ]; then
    if [ -f mvnw ]; then
        chmod +x mvnw && ./mvnw clean package -DskipTests
    else
        mvn clean package -DskipTests
    fi
    JAR_FILE=$(find target -name "*.jar" -not -name "*-sources.jar" | head -1)
elif [ "$BUILD_TOOL" = "gradle" ]; then
    if [ -f gradlew ]; then
        chmod +x gradlew && ./gradlew build -x test
    else
        gradle build -x test
    fi
    JAR_FILE=$(find build/libs -name "*.jar" -not -name "*-plain.jar" | head -1)
fi

echo "构建产物: $JAR_FILE"
```

### 编译失败处理

```bash
# 检查 Java 版本
java -version
grep -o "<java.version>.*</java.version>" pom.xml 2>/dev/null

# Maven 换阿里云源
mvn clean package -DskipTests -Dmaven.repo.remote=https://maven.aliyun.com/repository/public
```

---

## 配置数据库连接

```bash
CONFIG_FILE=$(find "$PROJECT_DIR" -path "*/resources/application*.properties" -o -path "*/resources/application*.yml" | head -1)

if [ -n "$CONFIG_FILE" ] && [ -n "$DB_PORT" ]; then
    sed -i "s|localhost:5432|localhost:${DB_PORT}|g" "$CONFIG_FILE" 2>/dev/null
    sed -i "s|localhost:3306|localhost:${DB_PORT}|g" "$CONFIG_FILE" 2>/dev/null
fi
```

---

## 启动

```bash
WEB_PORT=$(find_free_port 8080)
java -jar "$JAR_FILE" --server.port=${WEB_PORT} &
echo "Java 应用 → localhost:${WEB_PORT}"
```

---

## 清理

```bash
pkill -f "java.*${JAR_FILE}" 2>/dev/null
rm -rf "${PROJECT_DIR}/target" "${PROJECT_DIR}/build"
```
