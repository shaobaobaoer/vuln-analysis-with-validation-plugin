# MongoDB Setup

Prerequisite: `helpers/port-isolation.md` + `helpers/image-check.md`.

---

## Start

```bash
ensure_image "mongo:7"
MONGO_PORT=$(find_free_port 27017)

docker run -d \
    --name "setup_${PROJECT_NAME}_mongo" \
    --network "$SETUP_NETWORK" \
    -p ${MONGO_PORT}:27017 \
    mongo:7

wait_for_service "mongo" "$MONGO_PORT" "setup_${PROJECT_NAME}_mongo" 20
echo "MongoDB → localhost:${MONGO_PORT}"
```

## Connection Info

```
HOST=localhost / setup_${PROJECT_NAME}_mongo (inter-container)
PORT=${MONGO_PORT} / 27017 (inter-container)
URL=mongodb://localhost:${MONGO_PORT}/${PROJECT_NAME}
```

## Cleanup

```bash
docker rm -f "setup_${PROJECT_NAME}_mongo" 2>/dev/null
```
