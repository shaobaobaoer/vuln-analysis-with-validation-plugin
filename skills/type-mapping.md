# Vulnerability Type Mapping (Authoritative Source)

All vulnerability findings MUST use one of the 9 supported type keys below. The `type` field is a **machine-readable lowercase key**, NEVER a descriptive English name.

## 9 Supported Types

| Type Key | Description |
|----------|-------------|
| `rce` | Remote Code Execution |
| `ssrf` | Server-Side Request Forgery |
| `insecure_deserialization` | Insecure Deserialization |
| `arbitrary_file_rw` | Arbitrary File Read/Write |
| `dos` | Denial of Service |
| `command_injection` | Command Injection |
| `sql_injection` | SQL Injection |
| `xss` | Cross-Site Scripting |
| `idor` | Insecure Direct Object Reference / Broken Access Control |

## Mapping: Descriptive Names to Type Keys

### MAP to `rce`

Arbitrary Code Execution, Arbitrary Code Execution (Safe Mode Bypass), Arbitrary Code Execution (Pickle Bypass), Arbitrary Code Execution (Numpy Pickle), Arbitrary Code Execution (CIFAR cPickle), Arbitrary Code Execution (Marshal Bytecode Injection), Arbitrary Code Execution via Pickle Deserialization, Arbitrary Code Execution via File Write, Remote Code Execution, Remote Code Execution (RCE), remote_code_execution, Code Injection, Code Injection via eval(), code_injection, Template Injection, SSTI (Server-Side Template Injection), SSTI / Code Injection, Prompt Injection / Jinja2 Template Injection, Sandbox Escape, Import Restriction Bypass, Remote Code Execution via Dynamic Module Loading

### MAP to `insecure_deserialization`

Insecure Deserialization, insecure deserialization, Insecure Deserialization (RCE), Insecure Deserialization (Pickle), Unsafe Deserialization, unsafe_deserialization, Unsafe Deserialization (HDF5 Legacy Format), Unsafe YAML Loading, yaml_deserialization, Arbitrary Code Execution via Deserialization, Unsafe Deserialization in DataPipe Decoder, deserialization

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

## EXCLUDE (Not Supported)

XXE (map to `arbitrary_file_rw` if file read occurs), Vertical Privilege Escalation / Admin Bypass (not IDOR — different attack), Information Disclosure, Hardcoded Credentials, Weak Cryptography, Log Spoofing, arbitrary_plugin_loading, credential_exposure_via_environment, insecure_temp_file, JWT Signature Not Verified, Default No-Auth Configuration, Self-XSS, CSV Injection, HTML Injection (no script execution), IDOR via UUID guessing (assumed unguessable)

**Rule**: If a finding cannot be mapped to one of the 9 types, it MUST be excluded. NEVER invent new type names.
