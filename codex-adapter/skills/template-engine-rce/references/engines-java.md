# Java Engines

## FreeMarker

Keep as `rce` candidate:
- `new Template("name", new StringReader(user_template), cfg)` then `.process(...)`

Escalate confidence when:
- `?new`, `Execute`, permissive class resolver, unrestricted object wrappers are visible

## Velocity

High-confidence candidate:
- `Velocity.evaluate(ctx, writer, "tag", user_template)`

## Thymeleaf / SpEL

Keep as candidate:
- `parser.parseExpression(user_expression).getValue(...)`
- `templateEngine.process(user_template, ctx)` when the attacker controls the template body

Exclude:
- View-name selection without template-body control
