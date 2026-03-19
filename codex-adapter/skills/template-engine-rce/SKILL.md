---
name: template-engine-rce
description: >
  Codex-side overlay for server-side template injection, template sandbox escape, and
  template-string-controlled render/compile vulnerabilities that lead to command execution.
  Use when scanning, filtering, generating PoCs, or validating findings involving Jinja2,
  Mako, Django templates, FreeMarker, Velocity, Thymeleaf/SpEL, EJS, Pug, Nunjucks,
  Handlebars, or Go text/template. This skill refines parent vulnerability-scanner,
  code-security-review, poc-writer, and validate-rce guidance and corrects false positives
  such as template-name-only control.
---

# Template Engine RCE Overlay

Use this skill as a Codex-side overlay on top of:

- `../vulnerability-scanner/SKILL.md`
- `../code-security-review/SKILL.md`
- `../poc-writer/SKILL.md`
- `../validate-rce/SKILL.md`

This skill does not replace the parent skills. It narrows and clarifies how to handle template-engine execution paths.

## When To Activate

- The user asks to improve support for SSTI, template sandbox escape, or template render RCE
- Static analysis finds render-from-string, template compilation, or expression-evaluation sinks
- A finding mentions Jinja2, Mako, Django templates, FreeMarker, Velocity, Thymeleaf, SpEL, EJS, Pug, Nunjucks, Handlebars, or Go `text/template`
- A candidate `rce` finding depends on user-controlled template strings

## Core Rules

1. Keep the final vulnerability type as `rce`. Do not invent a new top-level type.
2. Only treat the issue as template-engine `rce` if the attacker controls template source or an evaluated expression string, or if a sandbox escape path is specifically proven.
3. Exclude template-name-only and data-only cases from template-engine `rce`.
4. Treat `Markup(user_input)`, `mark_safe(user_input)`, and `|safe` as `xss` problems unless there is actual server-side evaluation.
5. Use `validate-rce` for confirmed command execution. Do not add a separate validator unless the workflow later requires it.

## Read Order

Read only the reference files needed for the current stage:

- Scanning and candidate generation: `references/scanner.md`
- Filtering and confidence decisions: `references/review.md`
- PoC generation: `references/poc.md`
- Runtime validation: `references/validation.md`
- Engine details:
  - Python: `references/engines-python.md`
  - Java: `references/engines-java.md`
  - Node.js / TypeScript: `references/engines-node.md`
  - Go: `references/engines-go.md`

## Integration Notes

- During `/vuln-scan`, use this skill after the parent scanner skill and before final filtering.
- During `/poc-gen`, use this skill only for `rce` findings sourced from template rendering.
- During `/reproduce`, use this skill only when the `rce` finding depends on a template payload or sandbox escape.

## Mandatory Classification

For every template-engine `rce` candidate, explicitly classify:

- `engine`
- `template_control`: `full_template`, `expression_fragment`, `template_name_only`, `data_only`
- `sandbox_mode`: `unsandboxed`, `sandboxed`, `unknown`
- `dangerous_context`
- `payload_family`

Store these as supplemental finding metadata in `workspace/vulnerabilities.json` or the raw candidate notes. Do not replace any required keys from the parent analyzer schema.

If `template_control` is `template_name_only` or `data_only`, exclude the candidate unless another independent execution sink exists.
