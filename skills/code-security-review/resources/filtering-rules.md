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
20. **Unrealistic attack prerequisites.** Vulnerabilities that require the attacker to already have full host access, root access, or equivalent administrative control. If the attacker already has the prerequisite capability, there is no marginal security impact.
21. **Executable model file formats.** Security issues arising from loading raw Python files, `.llama` files, or other model file formats that are inherently executable by design. Loading these file types is an explicit user action with known risk.
22. **Invalid TLS certificates.** Missing, expired, or self-signed TLS certificates in isolation. Certificate management is an operational concern, not a code-level security vulnerability.
23. **Payment or pricing plan bypasses.** Bypassing subscription tiers, quotas, or pricing gates when there is no broader security impact (e.g., no data leakage, no privilege escalation, no account compromise).
24. **Features requiring payment to exploit.** Vulnerabilities that can only be reached after paying for a specific product feature. The attacker must have a valid paid account and therefore a contractual relationship with the vendor.
25. **Missing HTTP security headers.** Absence of clickjacking protection headers (`X-Frame-Options`, `Content-Security-Policy: frame-ancestors`), missing `HttpOnly` cookie flags, missing `Secure` cookie flags, missing `HSTS` headers. These are defense-in-depth hardening measures, not exploitable vulnerabilities on their own.
26. **Image metadata not stripped.** EXIF or other metadata remaining in uploaded images. This is a privacy concern but not a security vulnerability unless the metadata directly enables exploitation (e.g., embedded scripts in metadata that execute).
27. **CSV injection.** Injecting formula payloads (e.g., `=cmd|...`) into CSV exports. This is only exploitable if a victim opens the file in a spreadsheet application and approves execution of macros — an unrealistic two-step user action entirely outside the server's control.
28. **Self-XSS or non-auto-triggering XSS.** XSS payloads that only execute when the victim pastes attacker-controlled content into their own browser console, or stored XSS that requires the victim to explicitly invoke a separate user action (beyond normal browsing) to trigger.

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
18. **Blind or limited SSRF**: SSRF where the attacker cannot read the response and cannot reach sensitive internal services (e.g., metadata endpoints, internal APIs) is informational. Only report SSRF if it provides actionable impact: access to cloud metadata, internal network scanning, or data exfiltration via out-of-band channels. Blind SSRF that only proves a connection was made has low security value.
19. **Command injection in local-only libraries**: Command injection in a library that is installed locally and not used as part of a network-accessible service is informational. **Exception**: If the library is commonly embedded in web applications or API servers where the injection input can arrive from remote users, report it — but explicitly document the remote exploitation path.
20. **HTML or Markdown injection in text fields**: Injecting HTML tags or Markdown formatting into text fields is informational unless it leads to XSS that executes automatically when another user views the content. Markdown that renders as bold text or inserts a link is not a vulnerability. **Exception**: XSS that fires immediately on page load or on normal navigation is a real finding.
21. **Session token expiry**: Missing session expiration or lack of token invalidation on logout is informational. These are best-practice recommendations, not exploitable vulnerabilities, unless there is a concrete attack path (e.g., shared device theft combined with a lack of server-side revocation).
22. **Local Pickle loading without networking**: A library that loads Pickle files from the local filesystem is informational — the user must already have the ability to place the Pickle file, which implies local access. **Exception**: Libraries with built-in networking components (HTTP servers, RPC endpoints, API servers) that accept Pickle-serialized data from remote users are valid `insecure_deserialization` findings — document the remote upload path explicitly. **Critical**: Do NOT report `pickle.load` / `torch.load` / `joblib.load` / `cloudpickle.load` as vulnerabilities unless there is an explicit, traceable path from an unauthenticated network request to the deserialization call. Model loading in ML libraries (`torch.load`, `tf.saved_model.load`, `safetensors.load_file`) where the caller must supply the model file path is **always informational** — the attacker must already control the filesystem to place the malicious model file.

23. **Builder-created HTTP endpoints wrapping library functions are NOT valid findings**: If the test harness (Dockerfile, `vuln_test_server.py`, inline server) creates an HTTP endpoint (e.g., `/v1/cache/load`, `/exec_code`, `/load`) that calls a library function (`pickle.load`, `exec()`, `torch.load`) directly on user-provided data, any "vulnerability" found through that endpoint is invalid — the endpoint does not exist in the original codebase. The finding traces to a builder-manufactured attack surface, not an original vulnerability. **Exclude** all such findings with reason `"Entry point is builder-manufactured — not present in original source"`.

24. **Duplicate findings sharing the same root-cause entry point**: If two or more findings share the same vulnerable function or HTTP endpoint as their root cause, only the highest-severity finding is kept. Additional findings against the same entry point must be merged into the primary finding's description or excluded. Exception: findings may be kept separately if they demonstrate completely different attack chains (e.g., both SSRF and RCE are possible through one endpoint via different mechanisms) — but must be explicitly noted as "same entry point, different attack chain".

25. **Builder workspace entry_point paths are invalid**: Any finding whose `entry_point.path` points to a file in the `workspace/` directory, or to a file named `test_server.py`, `harness.py`, `vuln_test_server.py`, or any builder-generated wrapper — is invalid regardless of what vulnerability is claimed. The entry point does not exist in the original repository. **Exclude** with reason `"Builder-generated entry point: path resolves to test harness file, not original source"`. Observed: TensorRT produced 5 findings all through `workspace/test_server.py` — all invalid; only source-level findings are legitimate.

26. **URL path traversal vs filesystem path traversal disambiguation**: A `../` sequence in an **HTTP URL path component** (e.g., `GET /api/../admin`) is resolved and normalized by the HTTP server before routing — it is NOT filesystem path traversal and should not be reported as `arbitrary_file_rw`. Only report path traversal if the user-controlled string is used as a **filesystem path** in application code after URL decoding: `os.path.join(base, user_input)`, `filepath.Join(base, input)`, `File.resolve(user_input)`, `fs.readFile(input)`, etc. Evidence required: trace the input from the HTTP handler to a filesystem call without `path.normalize()` + prefix check or `os.path.abspath()` + base directory assertion.

27. **Library target + HTTP endpoint findings are systematically invalid**: If the target is a pure library (no built-in HTTP server in original source), any finding whose attack path goes through an HTTP endpoint is almost certainly exploiting a builder-created Flask/FastAPI server, not the library itself. Root cause documented in 175-run audit: builder routinely creates endpoints like `/load_pickle`, `/eval`, `/file/read`, `/deserialize`, `/api/model/save` that don't exist in the original library. **Exclude** any library-target finding with `entry_point.type: "webapp_endpoint"` unless you can trace a specific route definition in the original git-cloned source code. Observed in: `requests`, `catboost`, `xgboost`, `chainer`, `pandas`, `mxnet`, `botocore`, `sqlalchemy`, `composio`, `transformers`. For library targets, all findings MUST have `entry_point.type: "library_api"` and `access_level: "local"`.

28. **SQL Injection Quality Gate** (apply to ALL sql_injection candidates):

A finding is **NOT SQL Injection** unless the target code constructs a SQL query string using **user-controlled input without parameterization**. Auto-exclude if:

| Situation | Decision |
|-----------|----------|
| ORM uses parameterized queries exclusively: `cursor.execute("SELECT ... WHERE id=%s", (id,))` | **EXCLUDE** — properly parameterized |
| SQLAlchemy ORM `.filter_by()`, `.filter()` with column objects — no raw string | **EXCLUDE** — ORM handles parameterization |
| Django ORM `.filter(field=value)`, `.get(pk=pk)` — no `.raw()` | **EXCLUDE** — ORM parameterized by default |
| `.raw(f"SELECT ... {user_input}")` or `.execute(f"... {user_input}")` | **KEEP** — string interpolation into SQL |
| `cursor.execute("SELECT ... " + user_input)` or `% user_input` (%-format) | **KEEP** — string concatenation |
| `db.session.execute(text(f"... {user_input}"))` | **KEEP** — raw SQL with interpolation |

**Evidence required**: Point to the exact line where user input flows into a SQL string **without parameterization**. Parameterized queries (where user input is passed as a tuple/list argument separate from the query string) are NOT vulnerable.

**NoSQL injection**: MongoDB `$where` with user input, Elasticsearch raw query strings with user input → also map to `sql_injection`. Exclude if using safe query builders (pymongo `.find({"field": user_value})` is safe — user_value is never executed as code).

29. **XSS Quality Gate** (apply to ALL xss candidates):

A finding is **NOT XSS** unless user-controlled content is rendered in an HTML response **without escaping** in a context where it would execute as JavaScript. Auto-exclude if:

| Situation | Decision |
|-----------|----------|
| Jinja2/Twig/Django template with `autoescaping=True` (default) | **EXCLUDE** — framework escapes by default |
| React JSX without `dangerouslySetInnerHTML` | **EXCLUDE** — React auto-escapes in JSX |
| Angular without `bypassSecurityTrustHtml` | **EXCLUDE** — Angular sanitizes by default |
| API endpoint that returns JSON (not HTML) | **EXCLUDE** — JSON responses don't execute JS in browsers |
| `flask.escape()`, `html.escape()`, `cgi.escape()` applied to user input before render | **EXCLUDE** — properly escaped |
| `Markup(user_input)` or `mark_safe(user_input)` or `| safe` on untrusted data | **KEEP** — explicitly bypasses escaping |
| `render_template_string(user_input)` where user controls the template | **KEEP** — SSTI → maps to `rce`, not `xss` |
| `response.write(user_input)` with Content-Type: text/html and no escaping | **KEEP** — reflected XSS |
| Stored user content rendered via `{{ content | safe }}` in template | **KEEP** — stored XSS |

**Self-XSS / non-auto-triggering XSS**: **EXCLUDE** payloads that only trigger when the victim manually executes them (browser console paste, about:blank eval). Only report XSS that fires automatically on normal page navigation or normal page load.

**Evidence required**: Point to the exact line where user input is rendered into HTML context without escaping. Must be server-side rendering, not client-side only. Include the Content-Type and template context.

**Template-engine crossover**: If user input becomes template source or expression text rather than plain HTML data, map the candidate to `rce` and apply `resources/template-engine-rce.md`. Template-name-only and fixed-template data-only cases are not template-engine `rce`.

30. **IDOR Quality Gate** (apply to ALL idor candidates):

A finding is **NOT IDOR** unless there is direct evidence that a user-controlled ID is used to access another user's resource **without an ownership check**. Auto-exclude if:

| Situation | Decision |
|-----------|----------|
| ID is a UUID / GUID (e.g., `uuid4()`, RFC 4122 format) | **EXCLUDE** — assumed unguessable (Precedent #2) |
| Endpoint is admin-only (`@admin_required`, `@staff_required`, admin panel URL) | **EXCLUDE** — intentional broad access for privileged users |
| ORM query scoped to current user: `Model.objects.filter(pk=id, user=request.user)` | **EXCLUDE** — ownership check present |
| Resource is public/shared (all authenticated users meant to access it) | **EXCLUDE** — no ownership boundary to violate |
| `@permission_classes([IsOwner])` or DRF `has_object_permission()` applied | **EXCLUDE** — object-level permission enforced |
| Django: `request.user.objects.get(pk=id)` or `get_object_or_404(Model, pk=id, user=request.user)` | **EXCLUDE** — properly scoped |
| `Model.objects.get(pk=id)` with NO ownership check, endpoint is user-specific | **KEEP** — IDOR |
| `db.query(Item).filter(Item.id == item_id).first()` with no `Item.owner == user` assertion | **KEEP** — IDOR |
| `find_by_id(params[:id])` without `current_user` scope in Rails | **KEEP** — IDOR |
| No auth check at all on user-specific endpoint | **KEEP** as `idor` (type: unauthenticated access) |

**Evidence required**: Identify the exact ORM/query call that retrieves the resource using a user-controlled ID, AND confirm the absence of an ownership filter or permission check before the resource is returned. Quote both the vulnerable line and confirm there is no `@permission_required` / `.filter(user=current_user)` in scope.

31. **JNDI Injection Quality Gate** — Java targets only (apply to ALL `jndi_injection` candidates):

A finding is **NOT JNDI Injection** unless user-controlled input flows into a **Log4j logger call** (or equivalent JNDI-resolving API) without sanitization. Auto-exclude if:

| Situation | Decision |
|-----------|----------|
| Target language is NOT Java | **EXCLUDE** — JNDI injection is Java-only |
| Log4j version ≥ 2.17.0 (patched Log4Shell) with default `log4j2.formatMsgNoLookups=true` | **EXCLUDE** — lookup feature disabled by default in patched versions |
| User input is sanitized before logger call: `input.replace("${", "")` or similar | **EXCLUDE** — JNDI lookup sequences stripped |
| Logger call uses `%s` parameter substitution without message formatting: `logger.info("{}", userInput)` with Log4j 2.17+ | **EXCLUDE** — parameter substitution does not trigger JNDI lookups |
| JNDI is called only with hardcoded strings (no user-controlled input in the lookup URL) | **EXCLUDE** — no injection vector |
| User input reaches `logger.info(userInput)` or `logger.error(userInput)` with unpatched Log4j 2 (< 2.17.0) | **KEEP** — classic Log4Shell path |
| User input reaches `LogManager.getLogger().log(level, userInput)` with unpatched Log4j 2 | **KEEP** — JNDI lookup via message format |
| Any HTTP request header (User-Agent, X-Forwarded-For, X-Api-Version) flows directly into a Log4j logger | **KEEP** — most common Log4Shell exploitation vector |

**Evidence required**: Identify the exact logger call site, confirm Log4j version (from `pom.xml` or `build.gradle`), and trace the user-controlled input path from HTTP handler to logger. CVSS 10.0 if unauthenticated; cite CVE-2021-44228 (Log4Shell) as the canonical disclosure.

**Scope**: `jndi_injection` findings are ONLY valid for Java `webapp` and `service` targets. All other languages → auto-exclude.

32. **Prototype Pollution Quality Gate** — JavaScript/TypeScript targets only (apply to ALL `prototype_pollution` candidates):

A finding is **NOT Prototype Pollution** unless untrusted input can set properties on `Object.prototype` (or `Array.prototype`) through an **unsafe recursive merge, deep clone, or property assignment** that does not block `__proto__`, `constructor`, or `prototype` keys.

| Situation | Decision |
|-----------|----------|
| Target language is NOT JavaScript or TypeScript | **EXCLUDE** — PP is JS/TS-only |
| Merge/clone function explicitly checks: `if (key === '__proto__')` or `hasOwnProperty` guard | **EXCLUDE** — protected against PP |
| lodash ≥ 4.17.21, merge-deep ≥ 3.0.3, or other patched version used | **EXCLUDE** — library patched for PP |
| `Object.assign({}, input)` (shallow merge only) | **EXCLUDE** — shallow merge cannot pollute `__proto__` |
| `JSON.parse(input)` followed by property access — no deep merge | **EXCLUDE** — JSON.parse does not restore `__proto__` chain |
| Deep merge of user-controlled JSON without `__proto__` key filtering into a mutable object | **KEEP** — classic PP vector |
| `qs.parse(req.query, { allowDots: true, allowPrototypes: true })` or similar opt-in | **KEEP** — explicit opt-in to unsafe behavior |
| Affected object is accessed by a template engine with known PP gadgets (EJS, Pug, Handlebars) | **KEEP** as RCE if gadget chain confirmed |
| Pollution only raises `isAdmin` flag or similar — no RCE gadget found | **KEEP** as `prototype_pollution` (privesc, not RCE) |

**Evidence required**: Identify (a) the unsafe merge/clone function, (b) the user-controlled input that reaches it, (c) the property (usually `__proto__` or `constructor.prototype`) that gets polluted, and (d) optionally the downstream gadget chain (EJS `outputFunctionName`, Pug `block`, etc.) if RCE is claimed. Distinguish CVSS 8.1 (RCE via gadget) from 6.5 (privesc only).

**Scope**: `prototype_pollution` findings are ONLY valid for JavaScript/TypeScript targets. All other languages → auto-exclude.

33. **Pickle Deserialization Quality Gate** — Python targets only (apply to ALL `pickle_deserialization` candidates):

A finding is **NOT Pickle Deserialization** unless there is a direct, traceable path from an **unauthenticated or low-privilege network request** to a `pickle.loads()`, `dill.loads()`, or `cloudpickle.loads()` call on attacker-supplied bytes.

| Situation | Decision |
|-----------|----------|
| Target language is NOT Python | **EXCLUDE** — pickle_deserialization is Python-only |
| `pickle.load(open(filepath))` where filepath is caller-supplied — no network | **EXCLUDE** — local access required; attacker must already control filesystem |
| `torch.load(url)` or `joblib.load(path)` where caller supplies the path | **EXCLUDE** — model loading from local path; applies filtering-rules rule #22 |
| `AutoModel.from_pretrained(url, trust_remote_code=True)` | **EXCLUDE** — explicit trust opt-in; attacker already controls remote code |
| HTTP endpoint that `base64.b64decode(request.data)` then passes to `pickle.loads()` | **KEEP** — network-accessible pickle deserialization → CRITICAL |
| Flask/FastAPI route that calls `pickle.loads(request.get_data())` | **KEEP** — direct network path to pickle execution |
| Background task queue (Celery/RQ) that deserializes pickle from Redis/RabbitMQ and Redis/RabbitMQ accessible from network | **KEEP** — if attacker can inject into the queue |
| `pickle.loads()` in a locally-invoked CLI tool (not network-accessible) | **EXCLUDE** — local access required; use `command_injection` type if CLI injection path exists |
| `yaml.load()` without `Loader=yaml.SafeLoader` — NOT pickle | **DO NOT use `pickle_deserialization`** — map to `insecure_deserialization` instead |

**Evidence required**: Identify the exact `pickle.loads()` (or `dill.loads()`/`cloudpickle.loads()`) call site, trace the input from an HTTP request parameter/body to that call, confirm no content-type check blocks binary payloads. CVSS 9.8 for unauthenticated; 8.8 for authenticated.

**Scope**: `pickle_deserialization` is ONLY valid for Python targets AND ONLY when there is a network-accessible path to the deserialization call. `yaml.load()`, `marshal.loads()`, `shelve.open()` → use `insecure_deserialization` type, not `pickle_deserialization`.

26. **Severity inflation**: A severity label must be calibrated against attack prerequisites. The following downgrade rules apply automatically:
    - Finding with `access_level: "local"` → maximum severity is **MEDIUM** (attacker already has local access)
    - `dos` with `access_level: "auth"` → maximum severity is **MEDIUM**
    - `insecure_deserialization` where `attacker_preconditions` describes filesystem write access → maximum severity is **MEDIUM**
    - Reserve **CRITICAL** for genuinely unauthenticated, single-step, network-accessible exploits with full impact
    - **Observed**: In 175 pipeline runs, 81% of findings were classified high/critical and 0% were low — calibrate deliberately.

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
