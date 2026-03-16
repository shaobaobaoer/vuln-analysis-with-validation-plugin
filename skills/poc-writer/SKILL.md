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
- The `/vuln-scan` pipeline reaches Step 4

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

### Library PoC Pattern
```python
# For library vulnerabilities: import and call public API
import sample_lib

def exploit(target, timeout):
    """Exploit via library's public API."""
    # Call the public function with malicious input
    payload = "__import__('os').system('/tmp/invoke')"
    result = sample_lib.parse(payload)  # Public API call
    return result

    # For class-based APIs:
    # obj = sample_lib.MyClass(malicious_config)    # Constructor
    # obj.process(malicious_input)                   # Instance method
    # sample_lib.MyClass.from_string(payload)        # Class method
    # sample_lib.MyClass.validate(payload)           # Static method
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
def exploit(target, timeout):
    """Exploit via CLI command."""
    import subprocess
    result = subprocess.run(
        ["docker", "exec", container, "tool", "--input", malicious_file],
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

## Output

- `workspace/poc_scripts/poc_<type>_<id>.py` — One script per vulnerability
- `workspace/poc_manifest.json` — Manifest linking scripts to vulnerabilities
