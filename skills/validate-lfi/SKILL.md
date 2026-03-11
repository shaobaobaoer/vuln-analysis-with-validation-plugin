---
name: validate-lfi
description: Validate local file inclusion vulnerabilities by injecting file paths and checking for file content signatures in responses.
origin: vuln-analysis
---

# Validator: Local File Inclusion (LFI)

Confirm whether a vulnerability allows including and reading local server files.

## When to Activate

- An LFI vulnerability needs validation during reproduction (Step 5/7)

## Validation Logic

1. Identify the inclusion parameter
2. Construct LFI payloads: `/etc/passwd`, `/proc/self/environ`, `/proc/self/cmdline`, app config files
3. Check response body for file content indicators:
   - `/etc/passwd`: lines matching `username:x:uid:gid`
   - `/proc/self/environ`: contains `PATH=` or `HOME=`
   - Config files: contains expected keys/values

## Confirmation Criteria

| Status | Condition |
|--------|-----------|
| **CONFIRMED** | Response body contains recognizable content from the included file |
| **PARTIAL** | Response indicates file access (partial content, different error for existing vs non-existing) |
| **NOT_REPRODUCED** | No file content in response; generic error or 404 |

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | File content with known signatures returned (e.g., `/etc/passwd` lines) |
| 7-8 | Partial file content or PHP wrapper (`php://filter`) output returned |
| 4-6 | Different errors for existing vs non-existing files (info leak) |
| 1-3 | No file content, generic errors only |

**Threshold: Only mark CONFIRMED if Confidence >= 7**

## False Positive Checks

- Verify included content is NOT part of the application's normal response
- Test with a non-existing file path to confirm different behavior
- Distinguish from path traversal (LFI includes/processes, not just reads)
- **Exclude**: Findings in documentation or test files
