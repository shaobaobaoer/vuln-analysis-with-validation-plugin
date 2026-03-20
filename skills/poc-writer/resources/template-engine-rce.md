# Template-Engine RCE PoC Guidance

> **When to read**: Load this file when writing a PoC for an `rce` finding that depends on
> template rendering, expression evaluation, or sandbox escape.

## Selection Rules

1. Generate a template-engine payload first. Do not replace the real sink with a generic `eval` payload.
2. Only generate a template-engine `rce` PoC when `template_control` is `full_template` or `expression_fragment`, or when a specific sandbox escape is documented.
3. If the finding is `template_name_only` or `data_only`, do not generate a template-engine `rce` PoC.

## Payload Family Tags

| Engine | Payload Family |
|--------|----------------|
| Jinja2 | `jinja2-object-graph` or `jinja2-sandbox-escape` |
| Mako | `mako-python-exec` |
| Django templates | `django-filter-tag-abuse` |
| FreeMarker | `freemarker-new-builtin` |
| Velocity | `velocity-class-toolbox` |
| Thymeleaf / SpEL | `thymeleaf-spel` |
| EJS | `ejs-js-exec` |
| Pug | `pug-js-eval` |
| Nunjucks | `nunjucks-runtime-abuse` |
| Handlebars | `handlebars-helper-abuse` |
| Go `text/template` | `go-text-template-function-abuse` |

## PoC Requirements

- Execute `/tmp/invoke` through the template engine itself.
- Log the selected `engine` and `payload_family`.
- Verify the real entry point before sending the payload.
- Do not fake template-engine RCE with a generic code-injection payload if command execution is not justified by the finding.
