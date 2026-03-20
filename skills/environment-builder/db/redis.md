# Redis Setup

Prerequisite: `helpers/port-isolation.md` + `helpers/image-check.md`.

---

## Start

```bash
ensure_image "redis:7"
REDIS_PORT=$(find_free_port 6379)

docker run -d \
    --name "setup_${PROJECT_NAME}_redis" \
    --network "$SETUP_NETWORK" \
    -p ${REDIS_PORT}:6379 \
    redis:7

wait_for_service "redis" "$REDIS_PORT" "setup_${PROJECT_NAME}_redis" 15
echo "Redis → localhost:${REDIS_PORT}"
```

## Connection Info

```
HOST=localhost / setup_${PROJECT_NAME}_redis (inter-container)
PORT=${REDIS_PORT} / 6379 (inter-container)
URL=redis://localhost:${REDIS_PORT}/0
```

## Cleanup

```bash
docker rm -f "setup_${PROJECT_NAME}_redis" 2>/dev/null
```
