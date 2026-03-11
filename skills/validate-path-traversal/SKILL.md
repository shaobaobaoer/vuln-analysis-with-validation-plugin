---
name: validate-path-traversal
description: Validate path traversal vulnerabilities by constructing ../ sequences and verifying access to sensitive files like /etc/passwd.
origin: vuln-analysis
---

# Validator: Path Traversal

Confirm whether a path traversal vulnerability allows reading files outside the intended directory.

## When to Activate

- A path traversal vulnerability needs validation during reproduction (Step 5/7)
- PoC results need type-specific confirmation

## Validation Logic

1. Construct traversal payloads:
   - `../../../etc/passwd`
   - `..%2f..%2f..%2fetc%2fpasswd` (URL-encoded)
   - `....//....//....//etc/passwd` (double-dot bypass)
   - `..\/..\/..\/etc/passwd` (backslash variant)
2. Send the payload via the vulnerable parameter (URL path, query param, or POST body)
3. Check the response for known file signatures:
   - `/etc/passwd`: contains `root:x:0:0` or `root:` at line start
   - `/etc/shadow`: contains `root:$` (if readable)
   - Windows: `C:\Windows\win.ini` contains `[extensions]`
4. Verify the response status code is 200 (not 403/404)

## Confirmation Criteria

| Status | Condition |
|--------|-----------|
| **CONFIRMED** | Response body contains the target file's content |
| **PARTIAL** | Response returns 200 but file content is incomplete or filtered |
| **NOT_REPRODUCED** | Response is 403/404 or does not contain file content |

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | `/etc/passwd` content returned verbatim, multiple traversal depths work |
| 7-8 | File content returned but only one traversal variant works |
| 4-6 | Different error messages for valid vs invalid paths (info leak only) |
| 1-3 | No file content, just status code differences |

**Threshold: Only mark CONFIRMED if Confidence >= 7**

## False Positive Checks

- Ensure the baseline response (without traversal) does NOT contain the same content
- Verify traversal-specific content is present (not just a generic 200 response)
- **Precedent**: Path traversal in HTTP requests (using `../` in outbound URLs) is NOT a vulnerability — only relevant when reading local files
- **Exclude**: Findings in `.md` documentation files or test files
