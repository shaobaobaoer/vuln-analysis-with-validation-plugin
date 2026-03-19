# Retry & Fix Loop Template

> **Agent**: `agents/exploiter/AGENT.md §Phase 6`
> **Validation flow**: `templates/validation_framework.md`

When vulnerability reproduction fails, diagnose the cause and fix the PoC scripts or Docker environment. NEVER fix the target project's source code.

## Diagnosis Categories
| Diagnosis | Fix Strategy |
|-----------|-------------|
| `ENTRY_POINT_NOT_FOUND` | Re-analyze source, find correct entry point, or mark NOT_REPRODUCED |
| `ENV_ISSUE` | Modify Dockerfile, add packages, fix startup |
| `POC_BUG` | Fix PoC script logic, imports, assertions |
| `PARAM_MISMATCH` | Update endpoint, parameter names, payload format |
| `TIMING` | Increase wait times, add retry logic |
| `NOT_VULNERABLE` | Mark as NOT_REPRODUCED, skip further retries |

## Retry Rules
- Max **5 retries** per vulnerability
- Each retry must apply a **different** fix
- **Re-initialize monitoring** before each re-execution (restart listeners, clean markers)
- Re-run legitimacy check + type-specific validation after each attempt
