# Template-Engine RCE Quality Gate

> **When to read**: Load this file during Phase 2 when an `rce` candidate depends on template
> rendering, expression evaluation, or sandbox escape. This is subtype guidance for `rce`, not
> a standalone vulnerability class.

## Final-Keep Criteria

A finding is not final `rce` unless all of the following are true:

1. Attacker controls template source or expression text.
2. The controlled text reaches a render, compile, parse, or evaluate sink.
3. The engine is unsandboxed, or a concrete sandbox-escape path is visible.
4. Dangerous runtime objects, helpers, filters, globals, reflection APIs, or function maps are reachable.

## Auto-Exclude Cases

- Template name or view name only.
- Fixed template with attacker-controlled variables only.
- Auto-escaping disabled without server-side expression execution.
- `Markup`, `mark_safe`, `|safe`, or raw HTML output with no server-side evaluation.
- Sandbox claimed, but no dangerous context or escape path is visible.

## Confidence Guidance

| Scenario | Confidence |
|----------|------------|
| EJS, Pug, or Mako with full template-source control | 8-10 |
| Jinja2 with full template-source control and dangerous globals visible | 8-10 |
| FreeMarker or Velocity with direct render-from-string and dangerous runtime objects | 8-10 |
| Django templates, Handlebars, or Nunjucks with full template-source control but unclear escape path | 5-7 |
| Template-name-only or data-only control | 1-3 |

Only keep findings with confidence >= 7.

## Evidence Required In The Finding

- Exact render, compile, parse, or evaluate call.
- Exact entry point supplying the template string or expression text.
- Dangerous helper, object, reflection, or function-map path.
- Why this is server-side execution rather than `xss` or view selection.
