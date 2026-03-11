---
name: validate-xss
description: Validate XSS vulnerabilities by injecting script/event handler payloads and checking for unescaped reflection in HTML responses.
origin: vuln-analysis
---

# Validator: Cross-Site Scripting (XSS)

Confirm whether a vulnerability allows injecting client-side scripts into web pages.

## When to Activate

- An XSS vulnerability needs validation during reproduction (Step 5/7)

## Validation Logic

1. Inject payloads: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`
2. Check if payload appears **unescaped** in response HTML
3. Verify Content-Type is `text/html`
4. Check for CSP headers that would block execution

## Confirmation Criteria

| Status | Condition |
|--------|-----------|
| **CONFIRMED** | Payload appears unescaped in HTML response (`<script>` not `&lt;script&gt;`), Content-Type is text/html |
| **PARTIAL** | Payload partially encoded but some executable constructs survive |
| **NOT_REPRODUCED** | Payload fully escaped, stripped, or Content-Type prevents execution |

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | Unescaped `<script>` in HTML response, no CSP, Content-Type text/html |
| 7-8 | Event handler payload reflected unescaped, CSP may limit impact |
| 4-6 | Payload partially encoded, or response is JSON (not directly exploitable) |
| 1-3 | Payload fully escaped or in non-executable context |

**Threshold: Only mark CONFIRMED if Confidence >= 7**

## False Positive Checks

- Verify Content-Type is `text/html` (XSS in JSON is not directly exploitable)
- Check payload is in executable context (not inside HTML comment)
- Check for CSP header that would block inline scripts
- **Precedent**: React/Angular are secure by default. Only report with `dangerouslySetInnerHTML` or similar
- **Precedent**: Low-impact web vulns (tabnabbing, XS-Leaks, prototype pollution) — exclude unless extremely high confidence
