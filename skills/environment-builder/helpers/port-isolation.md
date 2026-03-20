# Port Isolation and Network Management

Before any submodule starts a container or service, execute the operations in this file first.

---

## Find Free Port

```bash
find_free_port() {
    local port=${1:-8000}
    local max_port=$((port + 100))
    while [ "$port" -le "$max_port" ]; do
        if ! ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            echo "$port"
            return 0
        fi
        port=$((port + 1))
    done
    echo "ERROR: No free port found in range ${1}-${max_port}" >&2
    return 1
}
```

---

## Create Project-Specific Docker Network

```bash
SETUP_NETWORK="setup_net_${PROJECT_NAME}"

docker network rm "$SETUP_NETWORK" 2>/dev/null || true
docker network create "$SETUP_NETWORK"
echo "Network created: $SETUP_NETWORK"
```

All subsequent `docker run` commands must include `--network "$SETUP_NETWORK"`.

---

## Wait for Service Ready

```bash
wait_for_port() {
    local port=$1
    local max_wait=${2:-30}
    local waited=0
    while [ "$waited" -lt "$max_wait" ]; do
        ss -tlnp 2>/dev/null | grep -q ":${port} " && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

wait_for_service() {
    local service_type=$1
    local port=$2
    local container_name=$3
    local max_wait=${4:-30}
    local waited=0

    wait_for_port "$port" "$max_wait" || return 1

    echo -n "Verifying ${service_type} service is ready"
    while [ "$waited" -lt "$max_wait" ]; do
        case "$service_type" in
            postgres)
                docker exec "$container_name" pg_isready -h localhost -U setup 2>/dev/null && { echo " OK"; return 0; } ;;
            mysql)
                docker exec "$container_name" mysqladmin ping -h localhost -u setup --password=setup123 2>/dev/null && { echo " OK"; return 0; } ;;
            redis)
                docker exec "$container_name" redis-cli ping 2>/dev/null | grep -q "PONG" && { echo " OK"; return 0; } ;;
            mongo)
                docker exec "$container_name" mongosh --eval "db.runCommand({ping:1})" 2>/dev/null && { echo " OK"; return 0; } ;;
            *)
                echo " Unknown service type"; return 0 ;;
        esac
        echo -n "."
        sleep 2
        waited=$((waited + 2))
    done
    echo " Timed out (${max_wait}s)"
    return 1
}
```

---

## Cleanup Network

```bash
docker network rm "setup_net_${PROJECT_NAME}" 2>/dev/null
```
