# Docker Compose / Dockerfile Setup

Used when the project comes with its own `docker-compose.yml` or `Dockerfile`.
This is the highest priority setup approach; when using this method, there is no need to read language-specific manual setup files.

Prerequisite: `helpers/port-isolation.md`.
If the compose file references external images, also need `helpers/image-check.md`.

---

## Option A: Docker Compose File Present

### Analyze Compose File

```bash
cd "$PROJECT_DIR"

COMPOSE_FILE=""
for f in docker-compose.yml docker-compose.yaml compose.yml compose.yaml; do
    [ -f "$f" ] && COMPOSE_FILE="$f" && break
done

echo "Compose file: $COMPOSE_FILE"
docker compose -f "$COMPOSE_FILE" config --services 2>/dev/null
```

### Handle Port Conflicts

```bash
WEB_PORT=$(find_free_port 8000)
export WEB_PORT=${WEB_PORT}
export DB_PORT=$(find_free_port 5432)

# If ports are hardcoded
cp "$COMPOSE_FILE" "${COMPOSE_FILE}.bak"
sed -i "s/\"8000:8000\"/\"${WEB_PORT}:8000\"/g" "$COMPOSE_FILE"
sed -i "s/\"8080:8080\"/\"${WEB_PORT}:8080\"/g" "$COMPOSE_FILE"
sed -i "s/\"3000:3000\"/\"${WEB_PORT}:3000\"/g" "$COMPOSE_FILE"
```

### Start

```bash
if [ -f .env.example ] && [ ! -f .env ]; then
    cp .env.example .env
fi

docker compose -f "$COMPOSE_FILE" up -d --build
docker compose -f "$COMPOSE_FILE" ps
```

---

## Option B: Dockerfile Only

```bash
cd "$PROJECT_DIR"
WEB_PORT=$(find_free_port 8000)

EXPOSE_PORT=$(grep -i "^EXPOSE" Dockerfile | head -1 | grep -oE "[0-9]+" | head -1)
EXPOSE_PORT=${EXPOSE_PORT:-8000}

docker build -t "setup_${PROJECT_NAME}" \
    --label "vuln-analysis.pipeline-id=${PIPELINE_ID}" .

docker run -d \
    --name "setup_${PROJECT_NAME}_web" \
    --network "$SETUP_NETWORK" \
    --label "vuln-analysis.pipeline-id=${PIPELINE_ID}" \
    -p ${WEB_PORT}:${EXPOSE_PORT} \
    "setup_${PROJECT_NAME}"

echo "App → localhost:${WEB_PORT} (container port ${EXPOSE_PORT})"
```

---

## Cleanup

```bash
# Compose method
docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null
[ -f "${COMPOSE_FILE}.bak" ] && mv "${COMPOSE_FILE}.bak" "$COMPOSE_FILE"

# Dockerfile method
docker rm -f "setup_${PROJECT_NAME}_web" 2>/dev/null
docker rmi "setup_${PROJECT_NAME}" 2>/dev/null
```
