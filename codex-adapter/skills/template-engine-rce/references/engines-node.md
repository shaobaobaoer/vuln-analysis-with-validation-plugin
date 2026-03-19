# Node / TypeScript Engines

## EJS

High-confidence candidate:
- `ejs.render(user_template, data)`
- `ejs.compile(user_template)(data)`

## Pug

High-confidence candidate:
- `pug.render(user_template, locals)`
- `pug.compile(user_template)(locals)`

## Nunjucks

Conditional candidate:
- `env.renderString(user_template, ctx)`

## Handlebars

Conditional candidate:
- `Handlebars.compile(user_template)(data)`

Exclude:
- `res.render(viewName)` without template-source control
