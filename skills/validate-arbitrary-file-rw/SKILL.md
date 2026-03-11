---
name: validate-arbitrary-file-rw
description: Validate arbitrary file read/write vulnerabilities by writing marker files and reading known system files.
origin: vuln-analysis
---

# Validator: Arbitrary File Read/Write

Confirm whether a vulnerability allows reading or writing files at arbitrary server paths.

## When to Activate

- An arbitrary file R/W vulnerability needs validation during reproduction (Step 5/7)

## Validation Logic

### File Write
1. Generate unique marker file path: `/tmp/vuln_write_test_<random>`
2. Write known content to that path
3. Verify via `docker exec <container> cat <path>`

### File Read
1. Target known file: `/etc/hostname`, `/proc/1/cmdline`
2. Send read payload through vulnerable vector
3. Verify response contains file content

## Confirmation Criteria

| Status | Condition |
|--------|-----------|
| **CONFIRMED** | Write: marker file exists with correct content. Read: response contains target file content |
| **PARTIAL** | Write: file created but truncated. Read: partial content returned |
| **NOT_REPRODUCED** | File operation blocked or does not execute |

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | Write: marker file created and read back. Read: sensitive file content returned |
| 7-8 | Write or read works but limited to specific directories |
| 4-6 | File operation errors differ for valid vs invalid paths |
| 1-3 | No file operation evidence |

**Threshold: Only mark CONFIRMED if Confidence >= 7**

## False Positive Checks

- For write: verify file did NOT exist before the test
- For read: ensure content is genuinely from the target file
- Test with different directories to confirm arbitrary (not just specific) access
- **Exclude**: Findings in test files or documentation files
