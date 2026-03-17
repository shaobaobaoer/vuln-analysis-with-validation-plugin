# Hard Exclusion Patterns (Regex-Based)

Pre-compiled regex patterns for the **first-pass, fast filter** applied before any AI-based analysis.

---

## How It Works

For each security finding, the **title** and **description** are concatenated and checked against these patterns. If any pattern matches, the finding is automatically excluded.

Additionally, **file-level rules** apply:
- Findings in **Markdown files** (`.md`) are unconditionally excluded.
- **Memory safety** findings are excluded unless the file is C/C++ (`.c`, `.cc`, `.cpp`, `.h`).
- **SSRF** findings are excluded if the file is an HTML file (`.html`).

---

## Pattern Groups

### 1. Generic DOS / Resource Exhaustion

**Exclusion Reason**: `Generic DOS/resource exhaustion finding (low signal)`

> **Exception**: Algorithmic/single-request DOS (ReDoS, XML bomb, hash collision, deeply nested input) are NOT excluded — they are valid `dos` type findings. Only generic rate-limiting and volumetric DOS are excluded here.

```regex
\b(resource exhaustion)\b                                                  [IGNORECASE]
\b(exhaust|overwhelm|overload).*?(resource|memory|cpu)\b                  [IGNORECASE]
\b(infinite|unbounded).*?(loop|recursion)\b                               [IGNORECASE]
```

**NOT excluded by this group** (valid `dos` findings):
- ReDoS / catastrophic backtracking
- XML bomb / billion laughs
- Hash collision attacks
- Deeply nested JSON/XML causing parser exhaustion
- Single-request algorithmic complexity attacks

### 2. Rate Limiting

**Exclusion Reason**: `Generic rate limiting recommendation`

```regex
\b(missing|lack of|no)\s+rate\s+limit                                    [IGNORECASE]
\brate\s+limiting\s+(missing|required|not implemented)                    [IGNORECASE]
\b(implement|add)\s+rate\s+limit                                         [IGNORECASE]
\bunlimited\s+(requests|calls|api)                                       [IGNORECASE]
```

### 3. Resource Management

**Exclusion Reason**: `Resource management finding (not a security vulnerability)`

```regex
\b(resource|memory|file)\s+leak\s+potential                              [IGNORECASE]
\bunclosed\s+(resource|file|connection)                                   [IGNORECASE]
\b(close|cleanup|release)\s+(resource|file|connection)                    [IGNORECASE]
\bpotential\s+memory\s+leak                                              [IGNORECASE]
\b(database|thread|socket|connection)\s+leak                              [IGNORECASE]
```

### 4. Open Redirect

**Exclusion Reason**: `Open redirect vulnerability (not high impact)`

```regex
\b(open redirect|unvalidated redirect)\b                                 [IGNORECASE]
\b(redirect.(attack|exploit|vulnerability))\b                            [IGNORECASE]
\b(malicious.redirect)\b                                                 [IGNORECASE]
```

### 5. Memory Safety (non-C/C++ only)

**Exclusion Reason**: `Memory safety finding in non-C/C++ code (not applicable)`

> Only applied when file extension is NOT in {`.c`, `.cc`, `.cpp`, `.h`}

```regex
\b(buffer overflow|stack overflow|heap overflow)\b                        [IGNORECASE]
\b(oob)\s+(read|write|access)\b                                          [IGNORECASE]
\b(out.?of.?bounds?)\b                                                   [IGNORECASE]
\b(memory safety|memory corruption)\b                                    [IGNORECASE]
\b(use.?after.?free|double.?free|null.?pointer.?dereference)\b           [IGNORECASE]
\b(segmentation fault|segfault|memory violation)\b                       [IGNORECASE]
\b(bounds check|boundary check|array bounds)\b                           [IGNORECASE]
\b(integer overflow|integer underflow|integer conversion)\b              [IGNORECASE]
\barbitrary.?(memory read|pointer dereference|memory address|memory pointer)\b [IGNORECASE]
```

### 6. Regex Injection

**Exclusion Reason**: `Regex injection finding (not applicable)`

> **Note**: Only regex **injection** (injecting untrusted content into a regex) is excluded. ReDoS (catastrophic backtracking from crafted input against a vulnerable regex) is a valid `dos` finding and is NOT excluded by this group.

```regex
\b(regex|regular expression)\s+injection\b                               [IGNORECASE]
\b(regex|regular expression)\s+flooding\b                                [IGNORECASE]
```

### 7. SSRF (HTML files only)

**Exclusion Reason**: `SSRF finding in HTML file (not applicable to client-side code)`

> Only applied when file extension is `.html`

```regex
\b(ssrf|server\s+.?side\s+.?request\s+.?forgery)\b                      [IGNORECASE]
```

---

## File-Level Rules Summary

| File Extension / Path | Rule |
|----------------------|------|
| `.md` | **All findings excluded** — "Finding in Markdown documentation file" |
| NOT `.c`, `.cc`, `.cpp`, `.h` | Memory safety findings excluded |
| `.html` | SSRF findings excluded |
| `test_*`, `*_test.*`, `__tests__/`, `tests/`, `spec/` | **All findings excluded** — "Finding in test file (not deployed)" |
| `examples/`, `example_*`, `demo/`, `benchmark/` | **All findings excluded** — "Finding in example/demo code (not deployed)" |

## Entry Point Context Rules

> These rules apply to the **file path and function context** of findings, not the title/description.

### Private/Internal Code Detection

**Exclusion Reason**: `Finding in private/internal code with no public entry point path`

For **library** projects, auto-flag findings in these locations for reachability review:

| Language | Private Indicator | Action |
|----------|------------------|--------|
| Python | Function/method starts with `_` (e.g., `_parse`, `__internal`) | Flag for reachability trace |
| Python | File in `_internal/`, `_utils/`, `_private/` directory | Flag for reachability trace |
| Go | Function/type starts with lowercase letter | Flag for reachability trace |
| Java | `private` or `protected` access modifier | Flag for reachability trace |
| JavaScript | Not exported from package entry point | Flag for reachability trace |

**Important**: Flagging ≠ auto-excluding. Private code COULD be called by a public function. The AI filtering step (§Entry Point Reachability Filter in `filtering-rules.md`) performs the actual call-path trace to determine if the finding is reachable.

---

## Implementation Reference

In Python, these patterns are pre-compiled using `re.compile()` with `re.IGNORECASE` flag:

```python
import re
from typing import List, Pattern

_GENERIC_DOS_PATTERNS: List[Pattern] = [
    re.compile(r'\b(resource exhaustion)\b', re.IGNORECASE),
    re.compile(r'\b(exhaust|overwhelm|overload).*?(resource|memory|cpu)\b', re.IGNORECASE),
    re.compile(r'\b(infinite|unbounded).*?(loop|recursion)\b', re.IGNORECASE),
    # NOTE: "denial of service" and "dos attack" removed — algorithmic DOS (ReDoS, XML bomb) is a valid finding
]

# Check a finding:
def should_exclude(title: str, description: str) -> bool:
    combined = f"{title} {description}".lower()
    for pattern in _GENERIC_DOS_PATTERNS:
        if pattern.search(combined):
            return True
    return False
```
