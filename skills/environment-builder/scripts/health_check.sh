#!/bin/bash
# health_check.sh - Verify project environment is ready
#
# Usage:
#   bash health_check.sh <project_name> <web_port> [services...]
#
# services format: <type>:<port>:<container_name>
#
# Examples:
#   bash health_check.sh myapp 8000
#   bash health_check.sh myapp 8000 postgres:5432:setup_myapp_postgres
#   bash health_check.sh myapp 8000 sqlite
#   bash health_check.sh myapp none   # ML project with no web port
#
# Environment variables:
#   QUIET=true  -> quiet mode, only output machine-readable results
#   QUIET=false -> full mode, with colors (default)

PROJECT_NAME=${1:?"Usage: health_check.sh <project_name> <web_port|none> [services...]"}
WEB_PORT=${2:?"Missing web_port parameter (use none if no web port)"}
shift 2
SERVICES=("$@")

QUIET=${QUIET:-false}

# Colors & counters
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0; FAIL=0; WARN=0
FAILURE_MSGS=()
WARN_MSGS=()

check() {
    local name="$1" result="$2" msg="$3"
    if [ "$result" -eq 0 ]; then
        ((PASS++))
        [ "$QUIET" != "true" ] && echo -e "  ${GREEN}OK $name${NC}: $msg"
    elif [ "$result" -eq 2 ]; then
        ((WARN++))
        WARN_MSGS+=("${name}: ${msg}")
        [ "$QUIET" != "true" ] && echo -e "  ${YELLOW}WARN $name${NC}: $msg"
    else
        ((FAIL++))
        FAILURE_MSGS+=("${name}: ${msg}")
        [ "$QUIET" != "true" ] && echo -e "  ${RED}FAIL $name${NC}: $msg"
    fi
}

detail() { [ "$QUIET" != "true" ] && echo -e "$1"; }

port_listening() { ss -tlnp 2>/dev/null | grep -q ":${1} "; }

verify_db_connection() {
    local db_type="$1" port="$2" container="$3"
    case "$db_type" in
        postgres)
            [ -n "$container" ] && { docker exec "$container" pg_isready -h localhost -U setup 2>/dev/null; return $?; }
            PGPASSWORD=setup123 psql -h localhost -p "$port" -U setup -c "SELECT 1;" >/dev/null 2>&1; return $? ;;
        mysql)
            [ -n "$container" ] && { docker exec "$container" mysqladmin ping -h localhost -u setup --password=setup123 2>/dev/null; return $?; }
            mysqladmin ping -h localhost -P "$port" -u setup --password=setup123 2>/dev/null; return $? ;;
        redis)
            [ -n "$container" ] && { docker exec "$container" redis-cli ping 2>/dev/null | grep -q "PONG"; return $?; }
            redis-cli -p "$port" ping 2>/dev/null | grep -q "PONG"; return $? ;;
        mongo)
            [ -n "$container" ] && { docker exec "$container" mongosh --quiet --eval "db.runCommand({ping:1})" >/dev/null 2>&1; return $?; }
            mongosh --port "$port" --quiet --eval "db.runCommand({ping:1})" >/dev/null 2>&1; return $? ;;
        sqlite) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Begin checks ──

detail ""
detail "========================================="
detail " Environment Health Check: ${PROJECT_NAME}"
detail "========================================="

# 1. Web application check (skip when web_port=none)
if [ "$WEB_PORT" != "none" ]; then
    detail ""
    detail " ${CYAN}[Web Application]${NC}"

    if port_listening "$WEB_PORT"; then
        check "Port ${WEB_PORT}" 0 "listening"
    else
        check "Port ${WEB_PORT}" 1 "not listening"
    fi

    HTTP_OK=false
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "http://localhost:${WEB_PORT}/" 2>/dev/null)

    if [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 500 ]; then
        check "HTTP response" 0 "status code ${HTTP_CODE}"
        HTTP_OK=true
    else
        for path in "/api" "/health" "/login" "/admin" "/index.html"; do
            HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://localhost:${WEB_PORT}${path}" 2>/dev/null)
            if [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 500 ]; then
                check "HTTP response" 0 "status code ${HTTP_CODE} (via ${path})"
                HTTP_OK=true
                break
            fi
        done
        [ "$HTTP_OK" = "false" ] && check "HTTP response" 1 "unable to connect"
    fi
else
    detail ""
    detail " ${CYAN}[ML/Script Project - No Web Port]${NC}"
    check "Project type" 0 "ML/script project, skipping HTTP check"
fi

# 2. Database & service checks
if [ ${#SERVICES[@]} -gt 0 ]; then
    detail ""
    detail " ${CYAN}[Database & Services]${NC}"

    for svc in "${SERVICES[@]}"; do
        IFS=':' read -r SVC_TYPE SVC_PORT SVC_CONTAINER <<< "$svc"

        if [ "$SVC_TYPE" = "sqlite" ]; then
            check "SQLite" 0 "file database, no network service needed"
            continue
        fi

        if port_listening "$SVC_PORT"; then
            check "${SVC_TYPE} port ${SVC_PORT}" 0 "listening"
        else
            check "${SVC_TYPE} port ${SVC_PORT}" 1 "not listening"
            continue
        fi

        if [ -n "$SVC_CONTAINER" ]; then
            CONTAINER_STATUS=$(docker inspect --format='{{.State.Status}}' "$SVC_CONTAINER" 2>/dev/null)
            if [ "$CONTAINER_STATUS" = "running" ]; then
                check "${SVC_TYPE} container" 0 "${SVC_CONTAINER} running"
            elif [ -n "$CONTAINER_STATUS" ]; then
                check "${SVC_TYPE} container" 1 "${SVC_CONTAINER} status: ${CONTAINER_STATUS}"
                continue
            fi
        fi

        if verify_db_connection "$SVC_TYPE" "$SVC_PORT" "$SVC_CONTAINER"; then
            check "${SVC_TYPE} connection test" 0 "service available"
        else
            check "${SVC_TYPE} connection test" 2 "port open but service not ready"
        fi
    done
fi

# 3. Docker environment check
detail ""
detail " ${CYAN}[Docker Environment]${NC}"

RUNNING_CONTAINERS=$(docker ps --format '{{.Names}}' 2>/dev/null | grep "setup_${PROJECT_NAME}" || true)
RUNNING_COUNT=0
[ -n "$RUNNING_CONTAINERS" ] && RUNNING_COUNT=$(echo "$RUNNING_CONTAINERS" | wc -l)

if [ "$RUNNING_COUNT" -gt 0 ]; then
    check "Running containers" 0 "${RUNNING_COUNT} found"
else
    check "Running containers" 0 "no Docker containers (possibly local deployment)"
fi

EXITED_CONTAINERS=$(docker ps -a --filter "status=exited" --format '{{.Names}}' 2>/dev/null | grep "setup_${PROJECT_NAME}" || true)
EXITED_COUNT=0
[ -n "$EXITED_CONTAINERS" ] && EXITED_COUNT=$(echo "$EXITED_CONTAINERS" | wc -l)

[ "$EXITED_COUNT" -gt 0 ] && check "Crashed containers" 1 "${EXITED_COUNT} exited"

SETUP_NET="setup_net_${PROJECT_NAME}"
if docker network inspect "$SETUP_NET" >/dev/null 2>&1; then
    check "Docker network" 0 "${SETUP_NET} exists"
else
    check "Docker network" 2 "${SETUP_NET} does not exist (possibly local deployment)"
fi

# 4. System resources
detail ""
detail " ${CYAN}[System Resources]${NC}"

DISK_PCT=$(df / | awk 'NR==2{print $5}' | tr -d '%')
DISK_AVAIL=$(df -h / | awk 'NR==2{print $4}')
[ "$DISK_PCT" -gt 90 ] && check "Disk space" 2 "available ${DISK_AVAIL} (${DISK_PCT}% used)" || check "Disk space" 0 "available ${DISK_AVAIL}"

MEM_AVAIL=$(free -h 2>/dev/null | awk '/Mem:/{print $7}' || echo "unknown")
check "Available memory" 0 "${MEM_AVAIL}"

# GPU check (useful for ML projects)
if nvidia-smi >/dev/null 2>&1; then
    GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total,memory.free --format=csv,noheader 2>/dev/null | head -1)
    check "GPU" 0 "${GPU_INFO}"
fi

# ── Final result ──

if [ "$FAIL" -eq 0 ] && [ "$WARN" -eq 0 ]; then
    STATUS="READY"
elif [ "$FAIL" -eq 0 ]; then
    STATUS="PARTIAL"
else
    STATUS="FAILED"
fi

if [ "$QUIET" = "true" ]; then
    echo "HEALTH_STATUS=${STATUS}"
    echo "HEALTH_PASS=${PASS}"
    echo "HEALTH_FAIL=${FAIL}"
    echo "HEALTH_WARN=${WARN}"
    [ "$FAIL" -gt 0 ] && { echo "FAILURES:"; printf '  %s\n' "${FAILURE_MSGS[@]}"; }
    [ "$WARN" -gt 0 ] && { echo "WARNINGS:"; printf '  %s\n' "${WARN_MSGS[@]}"; }
else
    echo ""
    echo "========================================="
    if [ "$STATUS" = "READY" ]; then
        echo -e " Result: ${GREEN}READY${NC} (${PASS} checks passed)"
    elif [ "$STATUS" = "PARTIAL" ]; then
        echo -e " Result: ${YELLOW}PARTIAL${NC} (${PASS} passed, ${WARN} warnings)"
    else
        echo -e " Result: ${RED}FAILED${NC} (${PASS} passed, ${FAIL} failed, ${WARN} warnings)"
    fi
    echo "========================================="
    echo ""
fi

exit $FAIL
