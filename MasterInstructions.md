# Advanced VAPT System — Master Development Instruction

This document governs implementation methodology and operational constraints.

## Source of Truth

For every development cycle:

CURRENT LATEST main
→ READ README.md
→ READ Architecture.md
→ READ MasterInstructions.md
→ DEEP INSPECT
→ PRIORITY ANALYSIS
→ ROOT CAUSE
→ SURGICAL CHANGE
→ TEST
→ SECURITY REVIEW
→ RE-INSPECT
→ STATUS
→ COMMIT
→ NEXT ARCHITECTURE GATE

Never rely on stale SHAs, prior conversations, screenshots, assumptions, or old implementation state.

## Required Engineering Principles

Build an integrated, evidence-driven VAPT orchestration platform covering authorized network, web, API, host, infrastructure, TLS, configuration, cloud/container, vulnerability intelligence, correlation, risk, attack paths, validation, evidence, remediation, campaign orchestration, and reporting.

The system must support explicit scoping and authorization.

Do not intentionally bypass authorization, compromise unrelated third-party systems, or indiscriminately scan the public Internet.

Do not fabricate evidence, telemetry, findings, progress, or validation.

Prefer surgical, production-grade changes. Avoid unnecessary dependencies and unrelated cleanup.

Preserve existing UI/design continuity unless a UI change is explicitly requested.

## Priority Order

1. Core backend architecture
2. Security architecture
3. Data integrity
4. Assessment orchestration
5. Telemetry and observability
6. Provider interfaces
7. Discovery
8. Network assessment
9. Web/API assessment
10. Vulnerability correlation
11. Risk engine
12. Attack-path analysis
13. Evidence management
14. Authentication/authorization
15. Reliability/performance
16. Frontend/UI/UX
17. Reporting
18. Documentation and cleanup

## Completion Standard

No architecture gate may be called complete without appropriate testing and explicit validation. If a validation step cannot be performed, state that fact.

## Cycle Report

At the end of each cycle report:

### IMPLEMENTED
Exact changes.

### WHY
Root cause and architectural reason.

### VALIDATION
Tests, build, lint, runtime checks.

### SECURITY REVIEW
Security implications and controls.

### ARCHITECTURE ALIGNMENT
README.md, Architecture.md, MasterInstructions.md.

### CURRENT STATUS
Verified state.

### NEXT ARCHITECTURE GATE
Exactly one highest-priority next objective.

### RECOMMENDATIONS
Only materially useful recommendations.


## Mandatory Project Status Report

After every implementation/update cycle, maintain `PROJECT_STATUS.md` on `main`. Record the current gate and its exact state, root cause, implementation summary, changed files, validation commands and results, security-review findings, commit references, unresolved blockers, user-facing feedback/recommendations, and the single next priority. Distinguish the highest gate number reached from the number of gates fully validated; never inflate completion counts or mark a gate complete based only on code being committed. Update README.md and Architecture.md when the active gate's status or architecture changes. Local validation must be reported only after the user or an available execution environment confirms it against the exact revision.


## Gate 54 Validation Closure — COMPLETE

On 2026-10-14, the user confirmed focused schema migration tests, focused remediation tests, the full PostgreSQL-backed `python -m pytest -q -rs`, `ruff check .`, `git diff --check`, and package wheel build passed on `f0f4d543947f864ff05d6e7173839b105562cd2c`. Five Starlette deprecation warnings were non-failing.

## Gate 55 Validation Closure — COMPLETE

On 2026-10-14, the user confirmed 4 focused schema-migration tests, 14 focused remediation API/PostgreSQL tests, the full PostgreSQL-backed suite with no skip summary, Ruff, diff checks, and wheel build passed on `8dcb6974132713bf426b30bfc202260c9a5ff699`. The database trigger rejects UPDATE and DELETE against `audit_events` while allowing inserts. Five Starlette deprecation warnings were non-failing.

## Gate 56 Validation Closure — COMPLETE

On 2026-10-14, the user confirmed focused migration tests (4 passed), focused remediation API/PostgreSQL tests (14 passed), the full PostgreSQL-backed suite at 100% without a skip summary, Ruff, diff checks, and package wheel build on `4e96495a5ee85e23b35033f364f379120898d159`. Five Starlette deprecation warnings were non-failing.

## Current Gate Directive — Gate 57: Fail-Closed Audit Protection Drift Detection

Inspect the latest `main` revision first. Versioned migrations do not detect if required PostgreSQL audit triggers are later disabled, dropped, or altered while their migration records remain intact. Add startup verification for the append-only UPDATE/DELETE trigger and the TRUNCATE trigger, including presence, enabled state, expected trigger definition, and fail-closed function behavior. Add PostgreSQL regressions proving startup fails closed when a required trigger is disabled and resumes after the trigger is restored. Keep all checks PostgreSQL-backed, update README.md, Architecture.md, MasterInstructions.md, and PROJECT_STATUS.md, then validate focused migration tests, full PostgreSQL-backed `python -m pytest -q -rs`, Ruff, diff checks, and wheel build against the exact `main` SHA. If any check fails, fix it and remain on Gate 57.

Gate 57 initially failed its first focused test because trigger event ordering was validated through brittle `pg_get_triggerdef()` text matching. Fix the check using PostgreSQL catalog trigger-type bits, add missing-trigger coverage, and validate the new commit. If any check fails, fix it and remain on Gate 57.

The broader PostgreSQL concurrency run exposed a transaction-lifecycle defect: the audit catalog verifier's SELECT left psycopg in an implicit transaction, so the integration fixture's transaction context became a savepoint and retained TRUNCATE/DDL locks. The migration runner now commits after successful verification and rolls back after verification errors. Regression tests must prove initialization returns the connection to IDLE on success and fail-closed drift errors; rerun the isolated cross-instance concurrency test and all required PostgreSQL validation before completing Gate 57.
