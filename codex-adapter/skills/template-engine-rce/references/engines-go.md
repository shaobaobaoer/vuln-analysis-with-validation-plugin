# Go Engines

## text/template

Keep as candidate:
- `template.New("x").Parse(user_template).Execute(...)`
- `template.Must(template.New("x").Parse(user_template)).Execute(...)`

This is only a strong `rce` finding when the function map or execution context exposes dangerous callables. Without dangerous functions, it may remain conditional.

Exclude:
- `ExecuteTemplate(w, userTemplateName, data)` where the attacker controls only the template name
- `html/template` with attacker-controlled data only
