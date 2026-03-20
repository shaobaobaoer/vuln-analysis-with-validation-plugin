# Java Project Setup

Used when the project has no Docker Compose / Dockerfile and is identified as a Java project.

Prerequisite: `helpers/port-isolation.md`.
Databases have already been started by `db/*.md`.

> **MANDATORY (vuln-analysis)**: In vulnerability analysis mode, all execution must be done inside Docker containers. Generate a Dockerfile first, then proceed with subsequent steps.

---

## Dockerfile Template (Java multi-stage build)

### Maven Project

```dockerfile
# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-<java_version> AS builder
WORKDIR /build

# Cache dependency layer
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

### Gradle Project

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

### Variable Substitution

| Placeholder | Replace With |
|--------|--------|
| `<java_version>` | `<java.version>` in `pom.xml` or `sourceCompatibility` in `build.gradle` (e.g. `17`, `21`); default `17` |
| `<port>` | Detected `server.port` (default `8080`) |

---

## Detect Build Tool

```bash
cd "$PROJECT_DIR"

if [ -f pom.xml ]; then
    BUILD_TOOL="maven"
elif [ -f build.gradle ] || [ -f build.gradle.kts ]; then
    BUILD_TOOL="gradle"
else
    echo "Unrecognized Java build tool"
fi
```

---

## Build

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

echo "Build artifact: $JAR_FILE"
```

### Build Failure Handling

```bash
# Check Java version
java -version
grep -o "<java.version>.*</java.version>" pom.xml 2>/dev/null

# Switch Maven to Alibaba Cloud mirror
mvn clean package -DskipTests -Dmaven.repo.remote=https://maven.aliyun.com/repository/public
```

---

## Configure Database Connection

```bash
CONFIG_FILE=$(find "$PROJECT_DIR" -path "*/resources/application*.properties" -o -path "*/resources/application*.yml" | head -1)

if [ -n "$CONFIG_FILE" ] && [ -n "$DB_PORT" ]; then
    sed -i "s|localhost:5432|localhost:${DB_PORT}|g" "$CONFIG_FILE" 2>/dev/null
    sed -i "s|localhost:3306|localhost:${DB_PORT}|g" "$CONFIG_FILE" 2>/dev/null
fi
```

---

## Start

```bash
WEB_PORT=$(find_free_port 8080)
java -jar "$JAR_FILE" --server.port=${WEB_PORT} &
echo "Java app → localhost:${WEB_PORT}"
```

---

## Cleanup

```bash
pkill -f "java.*${JAR_FILE}" 2>/dev/null
rm -rf "${PROJECT_DIR}/target" "${PROJECT_DIR}/build"
```
