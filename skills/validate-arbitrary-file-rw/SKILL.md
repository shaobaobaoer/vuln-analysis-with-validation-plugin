---
name: validate-arbitrary-file-rw
description: Validate arbitrary file read/write by monitoring /tmp/flag with inotifywait. Anti-cheat ensures file access is performed by the target app through the vulnerability, not by the PoC script directly.
origin: vuln-analysis
---

# Validator: Arbitrary File Read/Write

Confirm whether a vulnerability allows reading or writing files at arbitrary server paths, verified by `inotifywait` monitoring on `/tmp/flag`.

## When to Activate

- An arbitrary file R/W vulnerability needs validation during reproduction (Step 5/7)

## Prerequisites (set up before PoC execution)

```bash
# Create known flag file with unique content
docker exec <container> sh -c 'echo "FLAG_CONTENT_$(date +%s)" > /tmp/flag'

# Install inotify-tools (if not already present)
docker exec <container> sh -c 'apt-get install -y inotify-tools 2>/dev/null || apk add inotify-tools 2>/dev/null'

# Start file monitor in background
docker exec -d <container> sh -c 'timeout 60 inotifywait -m /tmp/flag -e access,modify,open,close_write --format "%T %e %f" --timefmt "%H:%M:%S" > /tmp/inotify_result.txt 2>&1 &'
```

## Success Criteria

### File Read

| Result | Condition |
|--------|-----------|
| **[SUCCESS]** | `inotifywait` detects `ACCESS` or `OPEN` on `/tmp/flag` AND legitimacy check passes |
| **[FAILED]** | No file access events detected within timeout |
| **[INVALID]** | PoC script directly reads `/tmp/flag` |

### File Write

| Result | Condition |
|--------|-----------|
| **[SUCCESS]** | `inotifywait` detects `MODIFY` or `CLOSE_WRITE` on `/tmp/flag` AND legitimacy check passes |
| **[FAILED]** | No file modification events detected within timeout |
| **[INVALID]** | PoC script directly writes to `/tmp/flag` |

## Attack Vector Examples

The PoC must exploit a vulnerability in the target application to make **the server** read or write `/tmp/flag`:

### File Read Vectors

| Technique | Payload Example |
|-----------|----------------|
| Path traversal | `GET /api/file?path=../../../../tmp/flag` |
| Template injection | `{{''.__class__.__mro__[1].__subclasses__()...open('/tmp/flag').read()}}` |
| XXE | `<!ENTITY xxe SYSTEM "file:///tmp/flag">` |
| PHP include | `?page=php://filter/convert.base64-encode/resource=/tmp/flag` |

### File Write Vectors

| Technique | Payload Example |
|-----------|----------------|
| File upload bypass | Upload to `../../../../tmp/flag` |
| Config overwrite | Write config pointing to `/tmp/flag` |
| Log injection | Inject content that writes to `/tmp/flag` |

## Legitimacy Check (Anti-Cheat)

Scan the PoC script source code. The result is `[INVALID]` if:

- `open('/tmp/flag')` or `open("/tmp/flag")` called directly in PoC code
- `cat /tmp/flag` or equivalent executed by the PoC via `os.system()`, `subprocess.run()`, etc.
- Direct file read/write to `/tmp/flag` in the PoC's own logic
- `pathlib.Path('/tmp/flag').read_text()` or equivalent in PoC code

**Rule**: The file access must happen through the **target application's vulnerable code path**, not by the PoC script directly. The PoC only sends HTTP requests to the target app's endpoints with path traversal or file inclusion payloads.

Example:
- VALID: `requests.get(target_url + "/api/file?path=../../../../tmp/flag")` — path injected as parameter
- INVALID: `open('/tmp/flag').read()` — PoC directly reads the file

## Verification

```bash
# Check for file read events
docker exec <container> cat /tmp/inotify_result.txt | grep -i "access\|open" && echo "[SUCCESS] File Read" || echo "[FAILED] File Read"

# Check for file write events
docker exec <container> cat /tmp/inotify_result.txt | grep -i "modify\|close_write" && echo "[SUCCESS] File Write" || echo "[FAILED] File Write"
```

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | `inotifywait` detects access/modify on `/tmp/flag`, file content returned in response |
| 7-8 | File access detected but content not visible in response (blind file read/write) |
| 4-6 | Error messages differ for valid vs invalid paths, suggesting file operation attempted |
| 1-3 | No file operation evidence |

**Threshold: Only mark [SUCCESS] if inotifywait event detected AND legitimacy check passed**

## Hard Exclusions

- File access limited to the application's own directory is NOT arbitrary file R/W
- File upload to intended upload directories is NOT a vulnerability
- Reading public/documentation files is NOT arbitrary file read
