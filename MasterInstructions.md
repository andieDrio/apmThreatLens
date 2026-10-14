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

## Gate 57 Validation Closure — COMPLETE

On 2026-10-14, the user confirmed the hardened main revision `db3b98165bb10351cb3fc2b10de964c44a5dcd90` passed all 8 PostgreSQL schema migration tests, the full PostgreSQL-backed `python -m pytest -q -rs` suite without a skip summary, `ruff check .`, `git diff --check`, and package wheel build. Five Starlette deprecation warnings were non-failing. The wheel SHA-256 was `b981c440324ff82895baf5bd5d20ca6b5f421ee20debdf98a40a561f316a5ed2`.

## Current Gate Directive — Gate 58: PostgreSQL Runtime/Migration Privilege Separation

Gate 58 implementation is committed directly to `main`; validation is pending. API startup now calls the read-only `verify_schema_ready()` boundary instead of running migrations. The explicit `python -m threatlens.storage.migrate` command uses `THREATLENS_MIGRATION_DATABASE_URL`, separate from the runtime `THREATLENS_DATABASE_URL`. Regression coverage checks readiness verification, prevents API startup from invoking migrations, and exercises PostgreSQL ACL denial for disabling/dropping audit triggers or replacing the trigger function.

Next, fetch/inspect the latest `main` and validate the exact revision. The focused PostgreSQL role test requires permission to create/drop a temporary role in the isolated test database. Run the focused migration and runtime-privilege tests, the full `python -m pytest -q -rs` suite without skips, Ruff, `git diff --check`, and package wheel build. Inspect any failure, fix it, and remain on Gate 58. Do not mark Gate 58 complete until the user confirms the exact-revision validation results. All changes stay directly on `main`: no feature branches, no branch switching to feature branches, and no pull requests.

All work must be committed directly to `main`: no feature branches, no switching to feature branches, and no pull requests. Do not rework completed gates absent a regression or blocker.
