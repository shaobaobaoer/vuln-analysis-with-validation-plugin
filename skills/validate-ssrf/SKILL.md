---
name: validate-ssrf
description: Validate SSRF vulnerabilities by injecting internal URLs and detecting outbound server requests via listeners or response content.
origin: vuln-analysis
---

# Validator: Server-Side Request Forgery (SSRF)

Confirm whether a vulnerability allows making the server send requests to unintended destinations.

## When to Activate

- An SSRF vulnerability needs validation during reproduction (Step 5/7)

## Validation Logic

1. Set up a detection mechanism (HTTP listener, internal metadata endpoint, or known local service)
2. Construct SSRF payloads:
   - Direct: `http://127.0.0.1:PORT/`
   - IP bypass: `http://0.0.0.0:PORT/`, `http://[::1]:PORT/`
   - DNS rebinding: domain resolving to 127.0.0.1
3. Inject the payload into the vulnerable parameter
4. Check for listener connection, internal data in response, or timing differences

## Confirmation Criteria

| Status | Condition |
|--------|-----------|
| **CONFIRMED** | Server makes request to attacker-controlled destination, or internal data returned |
| **PARTIAL** | URL was fetched but content is filtered/stripped |
| **NOT_REPRODUCED** | No outbound request; URL rejected or not fetched |

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | Listener receives connection from server, internal data returned |
| 7-8 | Response contains internal service data (e.g., metadata endpoint) |
| 4-6 | URL is fetched but content is fully stripped; timing differences only |
| 1-3 | No evidence of outbound request |

**Threshold: Only mark CONFIRMED if Confidence >= 7**

## False Positive Checks

- Verify the request originates from the server, not the client
- Ensure response data is from the internal target, not cached/default content
- **Hard Exclusion**: SSRF controlling only the path (not host/protocol) is NOT a vulnerability
- **Hard Exclusion**: SSRF in client-side JS/TS is NOT valid (can't bypass firewalls)
- **Hard Exclusion**: SSRF findings in `.html` files are excluded
