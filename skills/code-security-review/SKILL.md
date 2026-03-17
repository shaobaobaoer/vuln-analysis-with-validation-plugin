---
name: code-security-review
description: >
  AI-driven code security review with mandatory three-phase process: (1) Security Audit to produce raw findings,
  (2) False Positive Filtering with hard exclusions + AI-based confidence scoring, (3) Report with only high-confidence
  findings. Integrates regex-based auto-exclusion, 28 hard exclusion rules, 22 precedents, and 1-10 confidence scoring.
  Supports all programming languages. Derived from anthropics/claude-code-security-review.
origin: vuln-analysis
---

# Code Security Review

> **MANDATORY EXECUTION CONTRACT**
>
> This skill defines a **strictly ordered, three-phase process**.
> You MUST complete **all three phases in sequence** before producing final output.
> **You are FORBIDDEN from reporting any findings until Phase 3 is complete.**
> Skipping or abbreviating any phase is a critical failure.

## When to Activate

- Full security audit of a codebase is needed
- The `/vuln-scan` pipeline reaches Step 4 (Vulnerability Analysis)
- User requests code security review, audit, or vulnerability assessment
- Static analysis findings need false positive filtering

## Skill Resources

Before starting, you MUST read ALL of the following:

| Resource | Path | Read Requirement |
|----------|------|-----------------|
| Audit Prompt | `skills/code-security-review/resources/audit-prompt.md` | MUST read before Phase 1 |
| Hard Exclusion Patterns | `skills/code-security-review/resources/hard-exclusion-patterns.md` | MUST read before Phase 2 |
| False Positive Filtering Rules | `skills/code-security-review/resources/filtering-rules.md` | MUST read before Phase 2 |
| Customization Guide | `skills/code-security-review/resources/customization-guide.md` | Read if project-specific rules needed |

---

## PHASE 1: Security Audit

**Goal:** Produce a raw list of candidate findings. At this stage, do NOT filter — cast a wide net.

### Step 1a — Codebase Context Research

- Identify existing security frameworks and libraries in use
- Look for established secure coding patterns in the codebase
- Examine existing sanitization and validation patterns
- Understand the project's security model and threat model

### Step 1b — Comparative Analysis

- Compare target code against established security patterns
- Identify deviations from established secure practices
- Look for inconsistent security implementations
- Flag code that introduces new attack surfaces

### Step 1c — Vulnerability Assessment

Examine code for these security categories:

**Input Validation Vulnerabilities:**
- SQL injection, command injection, XXE, SSTI, NoSQL injection, path traversal

**Authentication & Authorization Issues:**
- Auth bypass, privilege escalation, session flaws, JWT vulnerabilities

**Crypto & Secrets Management:**
- Hardcoded keys/passwords, weak algorithms, improper key storage

**Injection & Code Execution:**
- RCE via deserialization, pickle injection, YAML deserialization, eval injection, XSS

**Data Exposure:**
- Sensitive data logging, PII violations, API leakage, debug info exposure

### Raw Finding Format

```
RAW FINDING #N
- Title: <short title>
- File: <path:line>
- Category: <e.g. rce, ssrf, command_injection>
- Severity: HIGH / MEDIUM / LOW
- Description: <what the bug is>
- Attack Path: <how an attacker exploits it step by step>
```

**Checkpoint — PHASE 1 COMPLETE when:** You have a complete raw findings list (can be 0 items).

---

## PHASE 2: Filter Findings (MANDATORY)

**Goal:** Remove false positives. This phase MUST be applied to every single item from Phase 1.

### Step 2a — Hard Exclusion Pass

Apply regex-based patterns from `resources/hard-exclusion-patterns.md`:

| Pattern Group | Auto-Exclude |
|--------------|-------------|
| DOS / Resource Exhaustion | `denial of service`, `dos attack`, `resource exhaustion` |
| Rate Limiting | `missing rate limit`, `implement rate limit` |
| Resource Management | `resource leak`, `unclosed resource`, `memory leak` |
| Open Redirect | `open redirect`, `unvalidated redirect` |
| Memory Safety (non-C/C++) | `buffer overflow`, `use-after-free`, `null pointer` |
| Regex Injection / ReDoS | `regex injection`, `regex denial of service` |
| SSRF (HTML files only) | `ssrf`, `server side request forgery` |

**File-level rules:**
- `.md` files → ALL findings excluded
- Non-C/C++ files → Memory safety findings excluded
- `.html` files → SSRF findings excluded

### Step 2b — AI Filtering Pass (28 Hard Exclusions)

Automatically exclude findings matching:

1. Denial of Service (DOS) — generic/volumetric only; single-request algorithmic DOS (ReDoS, XML bomb) is KEPT
2. Secrets/credentials stored on disk
3. Rate limiting concerns
4. Memory consumption or CPU exhaustion
5. Lack of input validation on non-critical fields
6. CI/CD input sanitization (unless untrusted input)
7. Lack of hardening measures
8. Theoretical race conditions/timing attacks
9. Outdated third-party libraries
10. Memory safety in memory-safe languages
11. Test files
12. Log spoofing
13. SSRF controlling only the path
14. AI prompt injection
15. Regex injection (not ReDoS)
16. Documentation files
17. Missing audit logs
18. Unavailable internal dependencies
19. Non-vulnerability crashes
20. Unrealistic attack prerequisites (requires full host/root access already)
21. Executable model file formats (`.py`, `.llama`, etc. loaded as model weights)
22. Invalid TLS certificates (operational concern, not code-level vulnerability)
23. Payment/pricing plan bypasses without broader security impact
24. Features requiring payment to exploit (paid account = contractual relationship)
25. Missing HTTP security headers (`X-Frame-Options`, `HttpOnly`, `Secure`, `HSTS`)
26. Image metadata not stripped (EXIF/metadata remaining in uploads)
27. CSV injection (requires victim to open file and approve macro execution)
28. Self-XSS or non-auto-triggering XSS

### Step 2c — Intended Functionality Check

Assess whether the exploitable behavior **exceeds the designed purpose** of the API. If the API is designed to perform the "dangerous" operation (e.g., `download_from_url()` fetching arbitrary URLs), the finding is by design — not a vulnerability. Apply rules from `resources/filtering-rules.md §Intended Functionality Exclusion`.

### Step 2d — Precedent Check (22 Precedents)

Apply specific guidance:

1. **Logging secrets**: High-value plaintext secrets = vulnerability. URLs = safe. Request headers = dangerous.
2. **UUIDs**: Assumed unguessable. UUID guessing = invalid attack.
3. **Audit logs**: Not a critical security feature.
4. **Environment variables/CLI flags**: Trusted values. Controlling env vars = invalid attack.
5. **Resource management**: Leaks are not vulnerabilities.
6. **Low-impact web vulns**: Tabnabbing, XS-Leaks, prototype pollution, open redirects — exclude unless extremely high confidence.
7. **Outdated libraries**: Managed separately.
8. **React/Angular XSS**: Secure by default. Only report with `dangerouslySetInnerHTML` or similar.
9. **CI/CD workflows**: Rarely exploitable in practice. Need concrete attack path.
10. **Client-side JS/TS permission checks**: Not vulnerabilities (backend responsible).
11. **MEDIUM findings**: Include only if obvious and concrete.
12. **Jupyter notebooks**: Rarely exploitable. Need concrete untrusted input path.
13. **Logging non-PII data**: Not a vulnerability unless exposing secrets/passwords/PII.
14. **Command injection in shell scripts**: Not exploitable without untrusted user input.
15. **SSRF in client-side JS/TS**: Not valid (can't bypass firewalls from client).
16. **Path traversal in HTTP requests**: `../` in HTTP requests is not a problem.
17. **Log query injection**: Only report if definitely exposing sensitive data to external users.
18. **Blind or limited SSRF**: Only report if attacker can read the response or reach sensitive internal services (cloud metadata, internal APIs). Blind SSRF with no actionable impact is informational.
19. **Command injection in local-only libraries**: Informational unless the library is commonly embedded in web apps/API servers where injection input can arrive from remote users.
20. **HTML or Markdown injection**: Informational unless XSS fires automatically on normal page navigation. Bold text or inserted links are not vulnerabilities.
21. **Session token expiry**: Informational — not exploitable without a concrete attack path (e.g., shared device theft + no server-side revocation).
22. **Local Pickle loading without networking**: Informational — local file placement implies local access. Exception: libraries with built-in HTTP/RPC servers that accept remote Pickle data.

### Step 2e — Confidence Scoring

| Score | Meaning | Action |
|-------|---------|--------|
| 1-3 | Low confidence, likely false positive | **EXCLUDE** |
| 4-6 | Medium confidence, needs investigation | **EXCLUDE** (unless very concrete) |
| 7-10 | High confidence, likely true vulnerability | **KEEP** |

**Rule: Any finding with Confidence < 7 MUST be excluded.**

### Filter Table (mandatory output)

| # | Title | Hard Excl? | Precedent Hit? | Concrete Attack Path? | Confidence (1-10) | Decision | Reason |
|---|-------|-----------|----------------|-----------------------|-------------------|----------|--------|

**Checkpoint — PHASE 2 COMPLETE when:** Every raw finding has a row in the filter table.

---

## PHASE 3: Report (Only KEPT Findings)

### Filter Summary Table

Show the Phase 2 table so the reader can see all filtering decisions.

### Detailed Finding Report (only KEPT items)

```
## Vuln N: <Category>: `<file:line>`

* Severity: HIGH / MEDIUM / LOW
* Confidence: <1-10 score> / 10
* Description: <what the vulnerability is>
* Exploit Scenario: <concrete step-by-step attack>
* Recommendation: <specific fix>
```

### Excluded Findings Summary

```
## Excluded Findings (N total)
| # | Title | Reason |
|---|-------|--------|
```

---

## Severity Reference

| Severity | Criteria |
|----------|----------|
| **HIGH** | Directly exploitable: RCE, data breach, authentication bypass |
| **MEDIUM** | Requires specific conditions but has significant impact |
| **LOW** | Defense-in-depth issues or lower-impact vulnerabilities |

## Anti-Patterns (MUST NOT Do)

- Do NOT report findings before completing Phase 2 filtering
- Do NOT use 0.0-1.0 confidence scores — the 1-10 scale is required
- Do NOT skip the filter table in the output
- Do NOT report a finding with Confidence < 7
- Do NOT combine Phase 1 and Phase 3 (no jumping from audit to report)
- Do NOT mentally filter without showing the filter table
