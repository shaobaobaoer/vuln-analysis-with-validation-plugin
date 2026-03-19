# Template-Engine RCE Validation

> **When to read**: Load this file together with `SKILL.md` when validating an `rce` finding
> that depends on template rendering, expression evaluation, or sandbox escape.

## Validation Rules

1. Use `/tmp/invoke` as the execution target, just like other `rce` validation.
2. The execution must happen through the real render, compile, parse, or evaluate path.
3. Template parse errors, reflected payload text, or HTML output alone are not confirmation.
4. If the engine is sandboxed, the evidence must demonstrate the escape or command-execution path, not only successful parsing.

## Anti-Cheat Clarification

The PoC may contain dangerous code strings as payloads, but the PoC itself must not directly execute:

- `os.system(...)`
- `subprocess.*(...)`
- `child_process.exec(...)`
- `Runtime.exec(...)`

Those APIs are valid only inside the payload string evaluated by the target engine.

## Accepted Evidence

- TCP listener on port 59875 receives `test_message`
- Equivalent marker proving `/tmp/invoke` ran through the target path
