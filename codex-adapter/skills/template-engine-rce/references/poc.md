# PoC Overlay

Apply this overlay during Step 5 for `rce` findings sourced from template rendering.

## PoC Selection Rules

1. Generate a template-engine-specific payload first. Do not default to a generic `eval` payload if the vulnerable sink is template rendering.
2. Only generate a template `rce` PoC when `template_control` is `full_template` or `expression_fragment`, or when a specific sandbox escape is documented.
3. If the finding is only `template_name_only` or `data_only`, do not generate a template-engine `rce` PoC.

## Payload Family Tags

- `jinja2-object-graph`
- `jinja2-sandbox-escape`
- `mako-python-exec`
- `django-filter-tag-abuse`
- `freemarker-new-builtin`
- `velocity-class-toolbox`
- `thymeleaf-spel`
- `ejs-js-exec`
- `pug-js-eval`
- `nunjucks-runtime-abuse`
- `handlebars-helper-abuse`
- `go-text-template-function-abuse`

## PoC Output Requirements

- The payload must execute `/tmp/invoke` through the template engine itself
- The PoC script must state the engine and payload family in comments or log output
- The PoC must verify the real entry point before firing the payload
- If command execution cannot be justified, do not fake it with a generic code-injection payload
