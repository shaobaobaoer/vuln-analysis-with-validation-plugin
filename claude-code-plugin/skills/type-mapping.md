# Vulnerability Type Mapping (Authoritative Source)

All vulnerability findings MUST use one of the 12 supported type keys below. The `type` field is a **machine-readable lowercase key**, NEVER a descriptive English name.

## 12 Supported Types

| Type Key | Description | Language Scope |
|----------|-------------|---------------|
| `rce` | Remote Code Execution | All |
| `ssrf` | Server-Side Request Forgery | All |
| `insecure_deserialization` | Insecure Deserialization | All |
| `arbitrary_file_rw` | Arbitrary File Read/Write | All |
| `dos` | Denial of Service | All |
| `command_injection` | Command Injection | All |
| `sql_injection` | SQL Injection | All |
| `xss` | Cross-Site Scripting | All |
| `idor` | Insecure Direct Object Reference / Broken Access Control | All |
| `jndi_injection` | JNDI Injection (Log4Shell pattern) | **Java only** |
| `prototype_pollution` | Prototype Chain Pollution | **JavaScript / TypeScript only** |
| `pickle_deserialization` | Python Pickle RCE via `__reduce__` | **Python only** |

## Mapping: Descriptive Names to Type Keys

### MAP to `rce`

Arbitrary Code Execution, Arbitrary Code Execution (Safe Mode Bypass), Arbitrary Code Execution (Pickle Bypass), Arbitrary Code Execution (Numpy Pickle), Arbitrary Code Execution (CIFAR cPickle), Arbitrary Code Execution (Marshal Bytecode Injection), Arbitrary Code Execution via Pickle Deserialization, Arbitrary Code Execution via File Write, Remote Code Execution, Remote Code Execution (RCE), remote_code_execution, Code Injection, Code Injection via eval(), code_injection, Template Injection, SSTI (Server-Side Template Injection), SSTI / Code Injection, Prompt Injection / Jinja2 Template Injection, Sandbox Escape, Import Restriction Bypass, Remote Code Execution via Dynamic Module Loading

> **Template-engine scope rule**: SSTI, expression injection, and template sandbox escape stay under `rce`; do NOT create a separate type key. Keep only when the attacker controls template source or expression text, or a concrete sandbox escape path exists. Template-name-only control, view selection, and fixed-template data-only cases are excluded. `Markup`, `mark_safe`, and `|safe` without server-side evaluation stay under `xss`.

### MAP to `insecure_deserialization`

Insecure Deserialization, insecure deserialization, Insecure Deserialization (RCE), Unsafe Deserialization, unsafe_deserialization, Unsafe Deserialization (HDF5 Legacy Format), Unsafe YAML Loading, yaml_deserialization, Arbitrary Code Execution via Deserialization, Unsafe Deserialization in DataPipe Decoder, deserialization, ObjectInputStream RCE, Java deserialization gadget chain, XStream deserialization, Jackson enableDefaultTyping

> **Disambiguation**: "Insecure Deserialization (Pickle)" for **Python targets with network-accessible `pickle.loads()`** → use `pickle_deserialization` instead. `insecure_deserialization` covers: Java (ObjectInputStream), YAML unsafe load, Ruby Marshal, PHP unserialize, and Python `pickle.loads()` for LOCAL file loading only.

### MAP to `ssrf`

SSRF, Server-Side Request Forgery, Server-Side Request Forgery (SSRF), server-side request forgery (ssrf), SSRF (Server-Side Request Forgery), SSRF via DNS Rebinding (TOCTOU)

### MAP to `command_injection`

Command Injection, command injection, Command Injection via Environment Variable, command_injection_via_hostname, shell_injection_codedeploy, Shell Injection

### MAP to `arbitrary_file_rw`

Path Traversal, path_traversal, Path Traversal (commonprefix bypass), Zip Slip (Arbitrary File Write via Archive Extraction), LFI (Local File Inclusion), local_file_inclusion, s3_symlink_following, Unrestricted File Upload, Directory Traversal

### MAP to `dos`

Denial of Service, denial_of_service, Denial of Service (ReDoS / Resource Exhaustion), ReDoS, redos, XML Bomb, Decompression Bomb

### MAP to `sql_injection`

SQL Injection, sql_injection, SQLi, Blind SQL Injection, Error-Based SQL Injection, Time-Based Blind SQL Injection, Union-Based SQL Injection, Boolean-Based SQL Injection, Second-Order SQL Injection, NoSQL Injection, MongoDB Injection, CQL Injection

### MAP to `xss`

Cross-Site Scripting, XSS, xss, Reflected XSS, Stored XSS, Persistent XSS, DOM-Based XSS, DOM XSS, Cross-Site Scripting (XSS), cross_site_scripting, HTML Injection leading to XSS, Template Injection leading to client-side XSS

> **XSS Scope Rule**: Only auto-triggering XSS is valid. Self-XSS and non-auto-triggering stored XSS are excluded per filtering-rules.md rule #28. Reflected XSS that fires on normal navigation and stored XSS that auto-executes are VALID findings.

### MAP to `idor`

Insecure Direct Object Reference, IDOR, idor, Broken Access Control, Horizontal Privilege Escalation, Missing Authorization Check, Missing Ownership Verification, Unauthorized Resource Access, Cross-User Data Access, Object-Level Authorization Bypass, BOLA (Broken Object Level Authorization), Forced Browsing (user-owned resources), Access Control Bypass (horizontal)

> **IDOR Scope Rule**: Only horizontal privilege escalation (user A accessing user B's resources) or complete missing authentication on user-specific endpoints. UUID-based IDs are assumed unguessable (Precedent #2 — exclude). Admin-only resources are intentional (not IDOR). MUST have evidence the access control is absent (not just a theoretical missing check).

### MAP to `jndi_injection`

JNDI Injection, Log4Shell, Log4j RCE, Log4j2 RCE, CVE-2021-44228, JNDI Lookup via User Input, InitialContext.lookup injection, JndiTemplate injection, LDAP Injection via JNDI, RMI Injection via JNDI, Java Naming API Injection

> **JNDI Scope Rule**: Java targets only. Only valid if user-controlled input flows into a JNDI lookup or a logger call that evaluates `${jndi:...}`. Non-Java targets MUST NOT have `jndi_injection` findings.

### MAP to `prototype_pollution`

Prototype Pollution, prototype chain pollution, __proto__ injection, constructor.prototype injection, Object.prototype pollution, Lodash merge pollution, deepmerge pollution, qs allowPrototypes pollution

> **Prototype Pollution Scope Rule**: JavaScript/TypeScript/Node.js targets only. Only valid when there is a traceable path from user input to a deep-merge, recursive assign, or `__proto__`/`constructor.prototype` property write — AND either RCE via template gadget or privilege escalation is demonstrable. Generic prototype pollution without measurable impact is excluded. Non-JS/TS targets MUST NOT have `prototype_pollution` findings.

### MAP to `pickle_deserialization`

Pickle Deserialization, Python Pickle RCE, unsafe pickle.loads, pickle injection, pickle_rce, pickle deserialization RCE, Arbitrary Code Execution via Pickle (network-accessible), dill deserialization, cloudpickle deserialization

> **Pickle Deserialization Scope Rule**: Python targets only. Only valid when `pickle.loads()` (or `dill.loads()`, `cloudpickle.loads()`) receives data over a **network channel** (HTTP request body, query parameter, WebSocket, socket). Local file loading (`pickle.load(open(path))` with caller-supplied path) is NOT this type — it is `insecure_deserialization` or excluded. ML model loading is excluded. Non-Python targets MUST NOT have `pickle_deserialization` findings.

## EXCLUDE (Not Supported)

XXE (map to `arbitrary_file_rw` if file read occurs), Vertical Privilege Escalation / Admin Bypass (not IDOR — different attack), Information Disclosure, Hardcoded Credentials, Weak Cryptography, Log Spoofing, arbitrary_plugin_loading, credential_exposure_via_environment, insecure_temp_file, JWT Signature Not Verified, Default No-Auth Configuration, Self-XSS, CSV Injection, HTML Injection (no script execution), IDOR via UUID guessing (assumed unguessable), Prototype Pollution without measurable impact (no RCE gadget, no privilege bypass), Pickle loading of local files without network path

**Rule**: If a finding cannot be mapped to one of the 12 types, it MUST be excluded. NEVER invent new type names.
