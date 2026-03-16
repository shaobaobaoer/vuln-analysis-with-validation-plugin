# Vulnerability Type Mapping (Authoritative Source)

All vulnerability findings MUST use one of the 6 supported type keys below. The `type` field is a **machine-readable lowercase key**, NEVER a descriptive English name.

## 6 Supported Types

| Type Key | Description |
|----------|-------------|
| `rce` | Remote Code Execution |
| `ssrf` | Server-Side Request Forgery |
| `insecure_deserialization` | Insecure Deserialization |
| `arbitrary_file_rw` | Arbitrary File Read/Write |
| `dos` | Denial of Service |
| `command_injection` | Command Injection |

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

## EXCLUDE (Not Supported)

SQL Injection, XXE, XSS, Authentication Bypass, Broken Access Control, Information Disclosure, Hardcoded Credentials, Weak Cryptography, IDOR, Log Spoofing, arbitrary_plugin_loading, credential_exposure_via_environment, insecure_temp_file, JWT Signature Not Verified, Default No-Auth Configuration

**Rule**: If a finding cannot be mapped to one of the 6 types, it MUST be excluded. NEVER invent new type names.
