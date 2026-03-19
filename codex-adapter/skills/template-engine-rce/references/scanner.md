# Scanner Overlay

Apply this overlay during Step 4 on top of the parent scanner rules.

## Template-Engine RCE Classification

For each candidate, record:

- `engine`: `jinja2`, `mako`, `django-template`, `freemarker`, `velocity`, `thymeleaf`, `spel`, `ejs`, `pug`, `nunjucks`, `handlebars`, `text-template`, or `unknown`
- `template_control`: `full_template`, `expression_fragment`, `template_name_only`, `data_only`
- `sandbox_mode`: `unsandboxed`, `sandboxed`, or `unknown`
- `dangerous_context`: helpers, filters, globals, Spring beans, runtime objects, reflection access
- `payload_family`

## Scanner Keep / Exclude Rules

| Situation | Scanner Action |
|-----------|----------------|
| User controls template source passed to `render`, `compile`, `evaluate`, `from_string`, or `Parse` | Keep as `rce` candidate |
| User controls an expression string later evaluated by SpEL / Thymeleaf / similar | Keep as `rce` candidate |
| User controls only template name / view name | Exclude from template-engine `rce` |
| User controls only template data in a fixed template | Exclude from template-engine `rce` |
| Engine is sandboxed but dangerous helpers / runtime objects are visible | Keep as sandbox-escape candidate |
| Engine is sandboxed and no dangerous context is visible | Keep only as conditional candidate |

## Corrections To Parent Heuristics

- `res.render(req.params.view)` is not template-engine `rce` by itself.
- `Jinja2Templates.TemplateResponse(name=user_input, ...)` is not template-engine `rce` by itself.
- `Markup(user_input)` or `|safe` is usually `xss`, not server-side code execution.
- `render_template_string(user_template)` is a template-engine `rce` candidate because the template source is attacker-controlled.

## Raw Finding Notes

The raw finding should describe:

1. The render / compile / evaluate sink
2. The exact user input that becomes template source or expression text
3. The dangerous context that makes code execution plausible
4. Why the behavior exceeds the API's intended purpose
