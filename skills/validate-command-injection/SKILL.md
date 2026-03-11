---
name: validate-command-injection
description: Validate command injection vulnerabilities by injecting shell metacharacters with unique markers and detecting execution in responses.
origin: vuln-analysis
---

# Validator: Command Injection

Confirm whether a vulnerability allows injecting and executing arbitrary OS commands.

## When to Activate

- A command injection vulnerability needs validation during reproduction (Step 5/7)

## Validation Logic

1. Generate unique marker: `CMD_INJECT_<random_hex>`
2. Construct payloads: `; echo MARKER`, `| echo MARKER`, `&& echo MARKER`, `` `echo MARKER` ``, `$(echo MARKER)`
3. Send through vulnerable parameter
4. Check response body and headers for marker

## Confirmation Criteria

| Status | Condition |
|--------|-----------|
| **CONFIRMED** | Unique marker appears in response or verifiable side-effect occurs |
| **PARTIAL** | Shell interpretation detected (e.g., "command not found") but marker not visible |
| **NOT_REPRODUCED** | Input properly sanitized; no shell interpretation |

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | Unique marker appears via shell execution, confirmed with second marker |
| 7-8 | Time-based blind injection confirmed (sleep causes expected delay) |
| 4-6 | Shell error messages visible but no execution proof |
| 1-3 | No shell interpretation evidence |

**Threshold: Only mark CONFIRMED if Confidence >= 7**

## False Positive Checks

- Verify marker is unique and cannot appear naturally
- Test with second marker for consistency
- Distinguish from reflected input (app echoing, not shell executing)
- **Precedent**: Command injection in shell scripts is generally NOT exploitable without untrusted user input
- **Precedent**: Environment variables and CLI flags are trusted — attacks requiring their control are NOT valid
