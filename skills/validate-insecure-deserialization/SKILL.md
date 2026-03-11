---
name: validate-insecure-deserialization
description: Validate insecure deserialization vulnerabilities by crafting malicious serialized objects (pickle, YAML) and verifying code execution.
origin: vuln-analysis
---

# Validator: Insecure Deserialization

Confirm whether a vulnerability allows code execution through malicious serialized objects.

## When to Activate

- An insecure deserialization vulnerability needs validation during reproduction (Step 5/7)

## Supported Formats

| Language | Format |
|----------|--------|
| Python | `pickle`, `PyYAML` (unsafe load), `shelve` |
| Java | `ObjectInputStream`, XML deserialization |
| PHP | `unserialize()` |
| Ruby | `Marshal.load()` |

## Validation Logic

1. Craft malicious payload (e.g., pickle with `os.system('echo MARKER > /tmp/deser_test')`)
2. Send serialized data to the vulnerable endpoint
3. Verify execution: check for marker file via `docker exec`, response content, or timing

## Confirmation Criteria

| Status | Condition |
|--------|-----------|
| **CONFIRMED** | Marker file exists or command output visible — code execution proven |
| **PARTIAL** | Deserialization occurs (different error for valid vs invalid) but execution not confirmed |
| **NOT_REPRODUCED** | Input rejected, safely deserialized, or no deserialization evidence |

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | Marker file created via pickle/YAML gadget, code execution proven |
| 7-8 | Deserialization with observable side-effects (timing, error differences) |
| 4-6 | Endpoint accepts serialized data but no execution evidence |
| 1-3 | Endpoint rejects or safely handles serialized input |

**Threshold: Only mark CONFIRMED if Confidence >= 7**

## False Positive Checks

- Verify marker is not pre-existing in the container
- Use unique marker values per test run
- Confirm safe deserialization does NOT trigger the same behavior
- **Precedent**: Memory safety issues in memory-safe languages (Python, Go, Java) are not applicable
