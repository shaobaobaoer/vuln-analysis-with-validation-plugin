# Review Overlay

Apply this overlay during false-positive filtering on top of the parent review rules.

## Template Engine RCE Quality Gate

A finding is **not** final `rce` unless all of the following are true:

1. Attacker controls template source or expression text
2. The controlled template reaches a render / compile / evaluate sink
3. The engine mode is either unsandboxed, or a sandbox escape path is specifically visible
4. There is a concrete execution path to dangerous runtime objects, helpers, filters, globals, or reflection APIs

## Auto-Exclude Cases

- Template name or view name only
- Fixed template with attacker-controlled variables only
- Auto-escaping disabled without server-side evaluation
- `Markup`, `mark_safe`, `|safe`, or raw HTML output with no server-side expression execution
- Sandbox advertised, but no dangerous context or escape path is visible

## Confidence Guidance

| Scenario | Confidence |
|----------|------------|
| EJS / Pug / Mako with full template-source control | 8-10 |
| Jinja2 with full template-source control and dangerous globals visible | 8-10 |
| FreeMarker / Velocity with direct render-from-string and dangerous runtime objects | 8-10 |
| Django templates / Handlebars / Nunjucks with full template-source control but unclear escape path | 5-7 |
| Template-name-only or data-only control | 1-3 |

Only keep findings with confidence >= 7.

## Evidence Required In The Finding

- Exact render / compile / evaluate call
- Exact entry point supplying the template string
- Dangerous helper / object / reflection path
- Why this is server-side execution rather than `xss` or view selection
