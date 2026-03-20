# PostgreSQL Setup

Prerequisite: `helpers/port-isolation.md` + `helpers/image-check.md`.

---

## Start

```bash
ensure_image "postgres:15"
DB_PORT=$(find_free_port 5432)
DB_TYPE="postgres"

docker run -d \
    --name "setup_${PROJECT_NAME}_postgres" \
    --network "$SETUP_NETWORK" \
    -p ${DB_PORT}:5432 \
    -e POSTGRES_USER=setup \
    -e POSTGRES_PASSWORD=setup123 \
    -e POSTGRES_DB="${PROJECT_NAME}" \
    postgres:15

wait_for_service "postgres" "$DB_PORT" "setup_${PROJECT_NAME}_postgres" 30
echo "PostgreSQL → localhost:${DB_PORT}"
```

## Connection Info

```
HOST=localhost / setup_${PROJECT_NAME}_postgres (inter-container)
PORT=${DB_PORT} / 5432 (inter-container)
USER=setup  PASSWORD=setup123  DATABASE=${PROJECT_NAME}
CONNECTION_STRING=postgresql://setup:setup123@localhost:${DB_PORT}/${PROJECT_NAME}
```

## Cleanup

```bash
docker rm -f "setup_${PROJECT_NAME}_postgres" 2>/dev/null
```
