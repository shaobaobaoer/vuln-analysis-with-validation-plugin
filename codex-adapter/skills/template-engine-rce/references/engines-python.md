# Python Engines

## Jinja2

Keep as `rce` candidate:
- `render_template_string(user_template)`
- `Environment(...).from_string(user_template).render(...)`
- `jinja2.Template(user_template).render(...)`

Conditional:
- `SandboxedEnvironment.from_string(user_template).render(...)` without visible dangerous globals

Usually exclude:
- `render_template("fixed.html", value=user_input)`
- `Markup(user_input)` or `|safe`

## Mako

High-confidence `rce` candidate:
- `Template(user_template).render(...)`

## Django Templates

Conditional candidate unless dangerous helpers are exposed:
- `Template(user_template).render(Context(...))`
- `Engine(...).from_string(user_template).render(...)`
