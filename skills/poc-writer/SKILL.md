---
name: poc-writer
description: Generate standalone Python PoC exploit scripts for each identified vulnerability. Scripts include configurable targets, timeout control, and validation assertions.
origin: vuln-analysis
---

# PoC Writer

Generate standalone Proof-of-Concept exploit scripts for identified vulnerabilities.

## When to Activate

- PoC scripts need to be generated for identified vulnerabilities
- The `/poc-gen` command is invoked
- The `/vuln-scan` pipeline reaches Step 5 (PoC Generation)

## Script Requirements

Each PoC script MUST:
1. Be independently runnable: `python3 poc_<type>_<id>.py --target <url>`
2. Accept `--target` argument (default: `http://localhost:8080`)
3. Have a `--timeout` argument (default: 30 seconds)
4. Print status: `[CONFIRMED]`, `[NOT_REPRODUCED]`, `[PARTIAL]`, or `[ERROR]`
5. Return exit code: 0 = confirmed, 1 = not reproduced, 2 = error
6. Include detailed logging for debugging
7. Use only: `requests` + standard library (no other external deps)
8. **Exploit through the correct entry point** — the entry point type determines the PoC approach:
   - **Web App endpoint**: Send HTTP requests to the specific endpoint (e.g., `requests.post(f"{target}/api/exec", ...)`)
   - **Library API**: Import the library and call the public function (e.g., `import sample_lib; sample_lib.parse(payload)`)
   - **CLI command**: Invoke the CLI tool with crafted arguments (e.g., `subprocess.run(["tool", "--input", malicious_file])`)
9. **Verify entry point exists** before sending payload — log which entry point is being tested

## Script Template

```python
#!/usr/bin/env python3
"""PoC for <VULN_ID>: <type> — <description>"""
import argparse
import sys
import time
import requests

def exploit(target, timeout):
    """Execute the exploit and return response data."""
    ...

def validate(response):
    """Validate whether the exploit succeeded. Returns bool."""
    ...

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    start = time.time()
    try:
        result = exploit(args.target, args.timeout)
        confirmed = validate(result)
        elapsed = time.time() - start
        status = "CONFIRMED" if confirmed else "NOT_REPRODUCED"
        print(f"[{status}] VULN_ID - {elapsed:.2f}s")
        sys.exit(0 if confirmed else 1)
    except Exception as e:
        print(f"[ERROR] VULN_ID - {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
```

## Entry Point-Specific PoC Patterns

### CRITICAL: All PoC Scripts Execute INSIDE Docker

**ALL PoC scripts — including library PoCs — MUST execute inside a Docker container.**

The exploiter agent copies PoC scripts into the Docker container and runs them via `docker exec`. PoC scripts MUST NOT:
- Use `importlib.util.spec_from_file_location()` to load modules from host paths
- Reference host filesystem paths like `/mnt/ecs-user/analysis/...` or `/tmp/vuln-target/...`
- Assume they run directly on the host machine

PoC scripts MUST:
- Import the target library normally (it's installed inside the Docker container)
- Use relative or container-internal paths only
- Work when executed via `docker exec <container> python3 /app/poc_scripts/poc_rce_001.py`

### Library PoC Pattern
```python
# For library vulnerabilities: import and call public API
# The library is installed inside the Docker container
import sample_lib  # Normal import — library is pip-installed in Docker

MARKER_FILE = '/tmp/vuln_rce_001_marker.txt'

def exploit(target, timeout):
    """Exploit via library's public API."""
    # Call the public function with malicious input
    payload = "__import__('os').system('echo VULN_CONFIRMED_rce_001 > /tmp/vuln_rce_001_marker.txt')"
    result = sample_lib.parse(payload)  # Public API call
    return result

def validate(result):
    """Check if the marker file was created."""
    import os
    return os.path.exists(MARKER_FILE)

    # For class-based APIs:
    # obj = sample_lib.MyClass(malicious_config)    # Constructor
    # obj.process(malicious_input)                   # Instance method
    # sample_lib.MyClass.from_string(payload)        # Class method
    # sample_lib.MyClass.validate(payload)           # Static method
```

**FORBIDDEN library PoC patterns:**
```python
# FORBIDDEN — loading module from host filesystem path
import importlib.util
spec = importlib.util.spec_from_file_location(
    'python_utils',
    '/mnt/ecs-user/analysis/keras/workspace/repo/keras/src/utils/python_utils.py'  # HOST PATH!
)

# FORBIDDEN — referencing host paths
MARKER_FILE = '/mnt/ecs-user/analysis/keras/workspace/markers/vuln001.txt'

# CORRECT — use normal import (library installed in Docker container)
import keras
from keras.src.utils import python_utils
MARKER_FILE = '/tmp/vuln_rce_001_marker.txt'
```

### Web App PoC Pattern
```python
# For web app vulnerabilities: send HTTP request to endpoint
def exploit(target, timeout):
    """Exploit via HTTP endpoint."""
    # Verify endpoint exists first
    check = requests.head(f"{target}/api/exec", timeout=5)
    if check.status_code == 404:
        print("[ERROR] Entry point /api/exec not found")
        return None
    # Send exploit payload
    return requests.post(f"{target}/api/exec", json={"code": payload}, timeout=timeout)
```

### CLI PoC Pattern
```python
# For CLI tool vulnerabilities: invoke via command line
# NOTE: The PoC itself runs inside Docker, so no `docker exec` wrapper needed
def exploit(target, timeout):
    """Exploit via CLI command."""
    import subprocess
    result = subprocess.run(
        ["tool", "--input", malicious_file],
        capture_output=True, text=True, timeout=timeout
    )
    return result
```

## Type-Specific Logic

| Type | Key Technique | Validation |
|------|--------------|------------|
| RCE | Unique marker via eval/exec/template injection | Marker in response |
| SSRF | Internal URL injection + listener | Listener receives connection |
| Insecure Deserialization | Malicious pickle/YAML payload | Marker file created |
| Arbitrary File R/W | Write marker, read it back | Marker file verified |
| DoS | ReDoS, nested JSON, XML bomb | 10x response time increase |
| Command Injection | Shell metacharacters + marker | Marker in response |

## Naming Convention (MANDATORY)

**Format**: `poc_<type>_<NNN>.py` — where `<type>` is one of the 6 supported vuln types and `<NNN>` is a 3-digit zero-padded sequential number.

**Valid examples**:
```
poc_rce_001.py
poc_ssrf_002.py
poc_command_injection_003.py
poc_insecure_deserialization_004.py
poc_arbitrary_file_rw_005.py
poc_dos_006.py
```

**ANTI-PATTERNS (FORBIDDEN — observed in actual pipeline runs)**:
```
poc_vuln_001_sql_injection.py    # WRONG: "vuln_001_" prefix, sql_injection is unsupported
poc_vuln_001_rce.py              # WRONG: "vuln_001_" prefix (don't embed vuln ID in name)
poc_vuln001_lambda_rce.py        # WRONG: "vuln001_" prefix with descriptive name
poc_vuln001_alias_cmd_injection.py  # WRONG: "vuln001_" prefix with descriptive name
poc_vuln002_safe_mode_bypass.py  # WRONG: "vuln002_" prefix with descriptive name
poc_vuln002_plugin_loading.py    # WRONG: "vuln002_" prefix with descriptive name
poc_001_rce.py                   # WRONG: number before type
poc_001_path_traversal_delete.py # WRONG: number before type, descriptive suffix
poc_001_pickle_rce.py            # WRONG: number before type, descriptive suffix
poc_001_auth_bypass.py           # WRONG: number before type, auth_bypass unsupported
poc_path_traversal_001.py        # WRONG: path_traversal is not a type (use arbitrary_file_rw)
poc_sql_injection_001.py         # WRONG: sql_injection is not a supported type
poc_RCE_001.py                   # WRONG: uppercase type
```

**The ONLY valid pattern is**: `poc_<type>_<NNN>.py` where `<type>` is exactly one of `rce`, `ssrf`, `insecure_deserialization`, `arbitrary_file_rw`, `dos`, `command_injection` and `<NNN>` is a 3-digit zero-padded number.

The `<type>` MUST be an exact match to one of: `rce`, `ssrf`, `insecure_deserialization`, `arbitrary_file_rw`, `dos`, `command_injection`.

## Output

- `workspace/poc_scripts/poc_<type>_<NNN>.py` — One script per vulnerability
- `workspace/poc_manifest.json` — Manifest linking scripts to vulnerabilities
