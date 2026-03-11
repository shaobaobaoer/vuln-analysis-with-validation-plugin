---
name: validate-dos
description: Validate denial of service vulnerabilities by comparing baseline response times against crafted payloads (ReDoS, nested JSON, XML bombs).
origin: vuln-analysis
---

# Validator: Denial of Service (DoS)

Confirm whether a vulnerability can make the service unavailable through crafted requests.

## When to Activate

- A DoS vulnerability needs validation during reproduction (Step 5/7)

## Validation Logic

1. Establish baseline (3 normal requests, average response time)
2. Send DoS payload (ReDoS, nested JSON, XML bomb, large payload)
3. Compare response time to baseline

## Confirmation Criteria

| Status | Condition |
|--------|-----------|
| **CONFIRMED** | Service crashes, unresponsive, or response time >= 10x baseline |
| **PARTIAL** | Significant slowdown but recovers; or requires multiple requests |
| **NOT_REPRODUCED** | Payload handled gracefully with normal response time |

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | Single request crashes the service or causes >10x response time |
| 7-8 | Significant slowdown (5-10x) from a single crafted request |
| 4-6 | Minor slowdown or requires multiple requests |
| 1-3 | No observable impact |

**Threshold: Only mark CONFIRMED if Confidence >= 7**

## False Positive Filtering

> **NOTE**: The `code-security-review` skill **hard-excludes** DOS from code audit reports. In the vuln-analysis pipeline, DoS is still tested dynamically but with lower priority.

- **Exclude**: Generic "unbounded loop" or "missing rate limiting" findings
- **Exclude**: Memory/CPU exhaustion requiring sustained high-volume traffic
- DoS findings from dynamic PoC testing are still valid if Confidence >= 7

## Safety Notes

- Only test against isolated containers
- Set strict timeouts on all requests
- Monitor container resource usage during testing
