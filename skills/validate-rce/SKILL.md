---
name: validate-rce
description: Validate remote code execution vulnerabilities using unique marker injection through eval, exec, template injection, and other vectors.
origin: vuln-analysis
---

# Validator: Remote Code Execution (RCE)

Confirm whether a vulnerability allows arbitrary code execution on the server.

## When to Activate

- An RCE vulnerability needs validation during reproduction (Step 5/7)

## Validation Logic

1. Generate a unique marker: `VULN_MARKER_<random_hex>`
2. Construct payloads to echo the marker:
   - Direct: `echo VULN_MARKER_abc123`
   - Via eval: `__import__('os').system('echo VULN_MARKER_abc123')`
   - Template injection: `{{config.__class__.__init__.__globals__['os'].popen('echo VULN_MARKER_abc123').read()}}`
3. Send the payload through the vulnerable vector
4. Check the response or side-effects for the unique marker

## Confirmation Criteria

| Status | Condition |
|--------|-----------|
| **CONFIRMED** | Unique marker appears in response body, headers, or observable output |
| **PARTIAL** | Signs of execution (timing, error messages) but marker not visible |
| **NOT_REPRODUCED** | No evidence of code execution |

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | Unique marker appears in response, verified with second marker |
| 7-8 | Command execution confirmed via timing (sleep) or file creation side-effect |
| 4-6 | Error messages suggest code interpretation but no execution proof |
| 1-3 | Theoretical path only, no observable execution |

**Threshold: Only mark CONFIRMED if Confidence >= 7**

## False Positive Checks

- Marker must be unique enough to not appear naturally
- Verify with a second, different marker for consistency
- Check that marker does not appear in baseline (non-exploit) responses
- **Precedent**: `eval()` in client-side JS/TS is NOT server-side RCE
- **Precedent**: Command injection in shell scripts is generally not exploitable without untrusted user input
