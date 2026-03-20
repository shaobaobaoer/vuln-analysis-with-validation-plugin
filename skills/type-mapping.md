# Vulnerability Type Routing (Authoritative Source)

This is the **single source of truth** for which vulnerability types are valid for a given language and target type. All agents and skills MUST consult this file before emitting findings.

## Routing Matrix: language x target_type → valid_vuln_types

### Universal Types (all languages)

| Type Key | Description | Valid Target Types |
|----------|-------------|--------------------|
| `rce` | Remote Code Execution (incl. SSTI, sandbox escape) | webapp, service, cli |
| `ssrf` | Server-Side Request Forgery | webapp, service |
| `command_injection` | Command Injection (shell=True, exec) | webapp, service, cli, library |
| `arbitrary_file_rw` | Arbitrary File Read/Write / Path Traversal | webapp, service, cli |
| `dos` | Denial of Service (ReDoS, resource exhaustion) | webapp, service, cli, library |
| `sql_injection` | SQL / NoSQL Injection | webapp, service |
| `xss` | Cross-Site Scripting (auto-triggering only) | webapp |
| `idor` | Insecure Direct Object Reference / BOLA | webapp |
| `insecure_deserialization` | Insecure Deserialization (non-pickle) | webapp, service |

### Language-Gated Types (HARD GATES — wrong language = immediate exclude)

| Type Key | Description | Language Gate | Valid Target Types |
|----------|-------------|--------------|-------------------|
| `jndi_injection` | JNDI Injection / Log4Shell | **Java only** | webapp, service |
| `pickle_deserialization` | Pickle RCE via `__reduce__` (network-accessible) | **Python only** | webapp, service |
| `prototype_pollution` | Prototype Chain Pollution | **JavaScript/TypeScript only** | webapp, service, library |

### Pre-computed Route Table

Use this table directly. The `valid_vuln_types` array for `target.json` is the intersection of language + target_type.

```
language=java,       target=webapp   → [rce, ssrf, sql_injection, xss, idor, command_injection, dos, arbitrary_file_rw, insecure_deserialization, jndi_injection]
language=java,       target=service  → [rce, ssrf, sql_injection, command_injection, dos, arbitrary_file_rw, insecure_deserialization, jndi_injection]
language=java,       target=cli      → [rce, command_injection, dos, arbitrary_file_rw]
language=java,       target=library  → [dos, command_injection]

language=python,     target=webapp   → [rce, ssrf, sql_injection, xss, idor, command_injection, dos, arbitrary_file_rw, insecure_deserialization, pickle_deserialization]
language=python,     target=service  → [rce, ssrf, sql_injection, command_injection, dos, arbitrary_file_rw, insecure_deserialization, pickle_deserialization]
language=python,     target=cli      → [rce, command_injection, dos, arbitrary_file_rw]
language=python,     target=library  → [dos, command_injection, pickle_deserialization]

language=typescript, target=webapp   → [rce, ssrf, sql_injection, xss, idor, command_injection, dos, arbitrary_file_rw, insecure_deserialization, prototype_pollution]
language=typescript, target=service  → [rce, ssrf, sql_injection, command_injection, dos, arbitrary_file_rw, insecure_deserialization, prototype_pollution]
language=typescript, target=cli      → [rce, command_injection, dos, arbitrary_file_rw]
language=typescript, target=library  → [dos, command_injection, prototype_pollution]

language=javascript, target=webapp   → [rce, ssrf, sql_injection, xss, idor, command_injection, dos, arbitrary_file_rw, insecure_deserialization, prototype_pollution]
language=javascript, target=service  → [rce, ssrf, sql_injection, command_injection, dos, arbitrary_file_rw, insecure_deserialization, prototype_pollution]
language=javascript, target=cli      → [rce, command_injection, dos, arbitrary_file_rw]
language=javascript, target=library  → [dos, command_injection, prototype_pollution]

language=go,         target=webapp   → [rce, ssrf, sql_injection, xss, idor, command_injection, dos, arbitrary_file_rw, insecure_deserialization]
language=go,         target=service  → [rce, ssrf, sql_injection, command_injection, dos, arbitrary_file_rw, insecure_deserialization]
language=go,         target=cli      → [rce, command_injection, dos, arbitrary_file_rw]
language=go,         target=library  → [dos, command_injection]
```

### Validator Routing

Each finding type maps to exactly one validator skill:

| Type Key | Validator Skill | Resources Loaded On-Demand |
|----------|----------------|---------------------------|
| `rce` | `skills/validate-rce/SKILL.md` | `resources/template-engine-rce.md` (if SSTI) |
| `ssrf` | `skills/validate-ssrf/SKILL.md` | — |
| `command_injection` | `skills/validate-command-injection/SKILL.md` | — |
| `arbitrary_file_rw` | `skills/validate-arbitrary-file-rw/SKILL.md` | — |
| `dos` | `skills/validate-dos/SKILL.md` | — |
| `sql_injection` | `skills/validate-sql-injection/SKILL.md` | — |
| `xss` | `skills/validate-xss/SKILL.md` | — |
| `idor` | `skills/validate-idor/SKILL.md` | — |
| `insecure_deserialization` | `skills/validate-insecure-deserialization/SKILL.md` | — |
| `jndi_injection` | `skills/validate-jndi-injection/SKILL.md` | — |
| `pickle_deserialization` | `skills/validate-pickle-deserialization/SKILL.md` | — |
| `prototype_pollution` | `skills/validate-prototype-pollution/SKILL.md` | — |

## Name-to-Key Mapping

When a CVE database or static analyzer reports a descriptive name, map it to the canonical type key:

| Descriptive Names | → Type Key |
|-------------------|-----------|
| Remote Code Execution, Code Injection, eval() injection, Dynamic Module Loading, SSTI, Template Injection, Sandbox Escape | `rce` |
| Server-Side Request Forgery, SSRF, DNS Rebinding | `ssrf` |
| Command Injection, Shell Injection, OS Command Injection | `command_injection` |
| Path Traversal, Zip Slip, LFI, Directory Traversal, Unrestricted File Upload | `arbitrary_file_rw` |
| Denial of Service, ReDoS, XML Bomb, Decompression Bomb, Resource Exhaustion | `dos` |
| SQL Injection, SQLi, Blind SQLi, NoSQL Injection, MongoDB Injection | `sql_injection` |
| Cross-Site Scripting, XSS, Reflected XSS, Stored XSS, DOM XSS | `xss` |
| IDOR, Broken Access Control, BOLA, Horizontal Privilege Escalation | `idor` |
| Insecure Deserialization, Unsafe YAML Loading, ObjectInputStream RCE, Jackson enableDefaultTyping | `insecure_deserialization` |
| JNDI Injection, Log4Shell, Log4j RCE, CVE-2021-44228, InitialContext.lookup | `jndi_injection` |
| Pickle Deserialization, pickle.loads RCE, dill/cloudpickle deserialization | `pickle_deserialization` |
| Prototype Pollution, `__proto__` injection, constructor.prototype pollution | `prototype_pollution` |

## Disambiguation Rules

- **SSTI / Template Injection** → `rce` (only if attacker controls template source or expression text)
- **Template-name-only control** → EXCLUDE (not exploitable)
- **`Markup`/`mark_safe`/`|safe`** → `xss` (not `rce`)
- **Pickle deserialization (local file only)** → `insecure_deserialization` (not `pickle_deserialization`)
- **Pickle deserialization (network-accessible)** → `pickle_deserialization` (Python only)
- **XSS (self-XSS, non-auto-triggering)** → EXCLUDE
- **IDOR via UUID** → EXCLUDE (assumed unguessable)
- **Vertical privilege escalation** → EXCLUDE (not IDOR)
- **Unmappable finding** → EXCLUDE (never invent new type keys)
