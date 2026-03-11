---
name: validate-idor
description: Validate IDOR/broken access control by testing cross-user resource access with manipulated object references.
origin: vuln-analysis
---

# Validator: Insecure Direct Object Reference (IDOR)

Confirm whether a vulnerability allows accessing resources belonging to other users.

## When to Activate

- An IDOR vulnerability needs validation during reproduction (Step 5/7)

## Validation Logic

1. Establish two test contexts (User A = victim, User B = attacker)
2. User B requests User A's resource using manipulated IDs
3. Compare response: does it contain User A's data?

## Confirmation Criteria

| Status | Condition |
|--------|-----------|
| **CONFIRMED** | User B can access User A's resource with full data returned |
| **PARTIAL** | User B receives some data but not all (partial access control) |
| **NOT_REPRODUCED** | Request returns 403/401, or no data from User A |

## Confidence Scoring (1-10)

| Score | Scenario |
|-------|----------|
| 9-10 | User B accesses User A's full resource data with different auth tokens |
| 7-8 | Partial data from User A returned to User B |
| 4-6 | Different response codes but no data leakage confirmed |
| 1-3 | Resource IDs are UUIDs (assumed unguessable) or shared resources |

**Threshold: Only mark CONFIRMED if Confidence >= 7**

## False Positive Checks

- Verify User B genuinely should NOT have access
- Confirm returned data belongs to User A (not default data)
- Test with unauthenticated request to distinguish missing auth vs IDOR
- **Precedent**: UUIDs are assumed unguessable — attacks requiring UUID guessing are NOT valid
- **Precedent**: Client-side JS/TS permission checks are NOT vulnerabilities (backend responsible)
