# False Positive Filtering Rules

This document contains the complete false positive filtering rule set. Use these rules to evaluate and filter findings produced by the security audit.

---

## Filtering Role

When filtering findings, act as a security expert reviewing results from a code audit.
Your task is to filter out false positives and low-signal findings to reduce alert fatigue.
You must maintain high recall (don't miss real vulnerabilities) while improving precision.

---

## Hard Exclusions

Automatically exclude findings matching these patterns:

1. **Generic Denial of Service (DOS)**: Rate limiting, volumetric flooding, resource exhaustion from sustained high traffic. **Exception**: Algorithmic/single-request DOS (ReDoS, XML bomb, hash collision, deeply nested input) that triggers worst-case behavior with a single crafted request — these are KEPT as `dos` type findings.
2. **Secrets/credentials stored on disk** — these are managed separately.
3. **Rate limiting concerns** or service overload scenarios. Services do not need to implement rate limiting.
4. **Memory consumption or CPU exhaustion** issues.
5. **Lack of input validation** on non-security-critical fields without proven security impact.
6. **Input sanitization concerns for CI/CD workflows** unless they are clearly triggerable via untrusted input.
7. **Lack of hardening measures.** Code is not expected to implement all security best practices, just avoid obvious vulnerabilities.
8. **Race conditions or timing attacks** that are theoretical rather than practical. Only report if extremely problematic.
9. **Outdated third-party libraries.** These are managed separately and should not be reported here.
10. **Memory safety issues in memory-safe languages.** Buffer overflows, use-after-free etc. are impossible in Rust, Go, Java, Python, etc. Do not report memory safety issues in these languages.
11. **Test files.** Files that are only unit tests or only used as part of running tests.
12. **Log spoofing.** Outputting un-sanitized user input to logs is not a vulnerability.
13. **SSRF controlling only the path.** SSRF is only a concern if it can control the host or protocol.
14. **AI prompt injection.** Including user-controlled content in AI system prompts is not a vulnerability.
15. **Regex injection.** Injecting untrusted content into a regex is not a vulnerability. **Exception**: ReDoS (catastrophic backtracking from crafted input against a vulnerable regex) IS a valid `dos` finding — do not exclude it.
16. **Insecure documentation.** Do not report findings in documentation files such as markdown files.
17. **Missing audit logs.** A lack of audit logs is not a vulnerability.
18. **Unavailable internal dependencies.** Depending on internal libraries that are not publicly available is not a vulnerability.
19. **Non-vulnerability crashes.** Code that crashes (e.g., undefined or null variable) but is not actually a vulnerability.

---

## Entry Point Reachability Filter (MANDATORY)

Before confidence scoring, assess whether each finding is **reachable** from a public entry point. This is the most critical quality filter — a vulnerability that cannot be reached by an attacker is not a real vulnerability.

### Reachability Rules

1. **Library projects**: The vulnerable code must be callable through the library's public API. If the vulnerability is in a private function (`_func` in Python, unexported in Go, non-`public` in Java) that is never called from any public API path, **EXCLUDE** it.
2. **Web applications**: The vulnerable code must be reachable from an HTTP endpoint. If the vulnerable function is an internal helper that no route handler calls, **EXCLUDE** it.
3. **CLI tools**: The vulnerable code must be reachable from CLI argument parsing. If the code is only used in tests or internal utilities, **EXCLUDE** it.
4. **Test-only code**: Vulnerabilities in test files, test fixtures, example scripts, or benchmark code are **EXCLUDED** regardless of type.
5. **Dead code**: Functions with no caller (not referenced anywhere and not part of the public API) are **EXCLUDED**.

### Reachability Confidence Adjustment

| Reachability | Adjustment | Rationale |
|-------------|------------|-----------|
| Clearly reachable from public entry point | **+2 confidence** | Attacker can definitely trigger this |
| Reachability ambiguous | **no adjustment** | Needs further investigation |
| Private/internal code with unclear call path | **-3 confidence** | Likely not exploitable |
| Test/example/dead code | **auto-exclude** | Never deployed to production |

### Entry Point Tracing

For each finding, trace backward from the vulnerable code:

```
REACHABLE example:
  eval(user_input) at views.py:42
    ↑ called by handler_func() at views.py:30
      ↑ registered as route: @app.route("/api/exec")
        = REACHABLE via POST /api/exec → KEEP

NOT REACHABLE example:
  eval(data) at _internal/parser.py:15
    ↑ called by _parse_unsafe() at _internal/parser.py:10
      ↑ NOT called from any public API function
        = NOT REACHABLE → EXCLUDE
```

---

## Intended Functionality Exclusion (MANDATORY)

A finding is only a valid vulnerability if the exploitable behavior **exceeds the designed purpose** of the entry point API. If the API is designed to perform the operation that constitutes the "vulnerability," it is working as intended — not a security flaw.

### Core Principle

> **Vulnerability = capability that the API was NOT designed to provide.**
>
> If the API's documented purpose already encompasses the "dangerous" operation, the finding is **by design**, not a bug.

### Decision Matrix

| API Designed Purpose | Observed Behavior | Vulnerability? | Reasoning |
|---------------------|-------------------|---------------|-----------|
| Logging / info display | Command injection via log input | **YES** | Command execution is not part of logging |
| Data parsing / formatting | RCE via `eval()` on parsed input | **YES** | Code execution is not part of parsing |
| Template rendering | SSTI leading to RCE | **YES** | Arbitrary code execution is not part of rendering |
| URL downloading / fetching | SSRF to internal services | **NO** | Fetching URLs is the API's designed purpose |
| Code execution / eval | Arbitrary code execution | **NO** | Running code is the API's designed purpose |
| File I/O with user-specified paths | Arbitrary file read/write | **NO** | File access with user paths is the designed behavior |
| Deserialization with `trust_remote=True` | Loading untrusted remote objects | **NO** | The parameter explicitly opts into trusting remote sources |
| Shell command builder | Command injection | **NO** | Constructing shell commands is the API's purpose |

### Application Rules

1. **Read the API's docstring/name/signature first**: Understand what the function is *supposed* to do before judging whether the behavior is anomalous.
2. **Opt-in trust parameters**: If the API has explicit trust parameters (e.g., `trust_remote=True`, `allow_pickle=True`, `safe=False`), behavior enabled by those parameters is **by design**. The user explicitly opted in.
3. **Scope escalation**: If the API's designed capability is limited (e.g., "read config files from a fixed directory") but the exploit escapes that scope (e.g., path traversal to read `/etc/passwd`), that IS a vulnerability — the behavior exceeds the designed scope.
4. **Side-channel exploitation**: If an API designed for purpose A can be abused to achieve unrelated purpose B (e.g., a logging function that allows RCE), that IS a vulnerability — purpose B is entirely outside the design intent.

### Confidence Adjustment

| Situation | Adjustment |
|-----------|------------|
| Exploitable behavior clearly outside API's designed purpose | **+2 confidence** |
| Exploitable behavior arguably within API's designed scope | **-3 confidence** |
| Behavior enabled by explicit opt-in trust parameter | **auto-exclude** |

---

## Precedents

Specific guidance for common security patterns:

1. **Logging secrets**: Logging high-value secrets in plaintext is a vulnerability. Logging URLs is assumed to be safe. Logging request headers is assumed to be dangerous since they likely contain credentials.
2. **UUIDs**: Can be assumed to be unguessable and do not need to be validated. If a vulnerability requires guessing a UUID, it is not valid.
3. **Audit logs**: Are not a critical security feature and should not be reported as a vulnerability if missing or modified.
4. **Environment variables and CLI flags**: Are trusted values. Attackers are not able to modify them in a secure environment. Any attack that relies on controlling an environment variable is invalid.
5. **Resource management**: Issues such as memory or file descriptor leaks are not valid vulnerabilities.
6. **Low-impact web vulnerabilities**: Tabnabbing, XS-Leaks, prototype pollution, and open redirects should not be reported unless extremely high confidence.
7. **Outdated libraries**: Managed separately; do not report.
8. **React/Angular XSS**: These frameworks are generally secure against XSS. Do not report XSS unless using `dangerouslySetInnerHTML`, `bypassSecurityTrustHtml`, or similar unsafe methods.
9. **CI/CD workflows**: Most vulnerabilities in CI/CD workflow files are not exploitable in practice. Before validating, ensure it is concrete with a very specific attack path.
10. **Client-side JS/TS permission checks**: A lack of permission checking or authentication in client-side code is not a vulnerability. Client-side code is not trusted. Backend is responsible for validation. Same applies for path-traversal and SSRF in client-side JS.
11. **MEDIUM findings**: Only include if they are obvious and concrete issues.
12. **Jupyter notebooks (*.ipynb)**: Most vulnerabilities are not exploitable in practice. Ensure concrete attack path with untrusted input.
13. **Logging non-PII data**: Not a vulnerability even if data may be sensitive. Only report if exposing secrets, passwords, or PII.
14. **Command injection in shell scripts**: Generally not exploitable since shell scripts generally do not run with untrusted user input. Only report if concrete attack path for untrusted input exists.
15. **SSRF in client-side JS/TS**: Not valid since client-side code cannot make server-side requests that bypass firewalls. Only report SSRF in server-side code.
16. **Path traversal in HTTP requests**: Using `../` is generally not a problem when triggering HTTP requests. Only relevant when reading files where `../` may allow accessing unintended files.
17. **Log query injection**: Generally not an issue. Only report if the injection will definitely lead to exposing sensitive data to external users.

---

## Signal Quality Criteria

For remaining findings, assess:

1. Is there a **concrete, exploitable vulnerability** with a clear attack path?
2. Does this represent a **real security risk** vs theoretical best practice?
3. Are there **specific code locations** and reproduction steps?
4. Would this finding be **actionable** for a security team?

---

## Confidence Scoring (1-10 scale)

| Score | Meaning | Action |
|-------|---------|--------|
| 1-3 | Low confidence, likely false positive or noise | **Exclude** |
| 4-6 | Medium confidence, needs investigation | **Exclude** (unless very concrete) |
| 7-10 | High confidence, likely true vulnerability | **Keep** |

> **Threshold**: Only keep findings with confidence score ≥ 7.

---

## Single Finding Analysis

For each finding, determine:

- **Severity**: The severity from the original finding (HIGH / MEDIUM / LOW)
- **Confidence Score**: 1-10 score based on criteria above
- **Keep or Exclude**: Whether to keep or exclude the finding
- **Exclusion Reason**: If excluded, the reason
- **Justification**: Explanation of the decision
