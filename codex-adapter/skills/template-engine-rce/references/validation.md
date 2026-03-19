# Validation Overlay

Apply this overlay together with `../../validate-rce/SKILL.md`.

## Validation Rules

1. Use `/tmp/invoke` as the execution target, just like normal `rce` validation.
2. The execution must happen through the template render / compile path.
3. A server-side parse error or template error without `/tmp/invoke` execution is not enough for confirmation.
4. If the engine is sandboxed, the validation evidence must demonstrate the escape path or execution path, not just template parsing.

## Anti-Cheat Clarification

The PoC may contain dangerous code strings as payloads, but the PoC itself must not directly execute:

- `os.system(...)`
- `subprocess.*(...)`
- `child_process.exec(...)`
- `Runtime.exec(...)`

Those APIs are valid inside the template payload string or expression if the target engine evaluates them.

## Validation Evidence

Accepted evidence remains:

- TCP listener on port 59875 receives `test_message`
- Equivalent marker showing `/tmp/invoke` really ran through the target path

Template parsing errors, reflected payload text, or rendered HTML alone are not enough.
