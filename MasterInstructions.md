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

## Gate 58 Validation Closure — COMPLETE

On 2026-10-14, the user confirmed exact-main revision `c39a7cd9d757e2a63cc27365e6e2b8e8a5e529b3` passed 37 focused PostgreSQL migration/runtime-privilege/API tests, the full PostgreSQL-backed `python -m pytest -q -rs` suite without a skip summary, `ruff check .`, `git diff --check`, and package wheel build. Wheel SHA-256: `6867d9542088c520678beee241b1fd26ebc0fb73885ea6f4c16bbc5f4bf1fb25`. Five Starlette deprecation warnings were non-failing. The user confirmed `HEAD == origin/main` and a clean working tree after removing only generated build artifacts.

## Gate 59 Validation Closure — COMPLETE

On 2026-10-14, the user confirmed exact-main revision `78f7856677d029c2f01d0000831b080e16c8f45c` passed 43 focused PostgreSQL migration/runtime-privilege/API tests, the full PostgreSQL-backed suite at 100% without a reported failure or skip summary, Ruff, `git diff --check`, and package wheel build. Wheel SHA-256: `f5315fe6366d53d9607e11aa1f4624978266c3e29a75376377bd17d03d63bb71`. Five Starlette deprecation warnings were non-failing. The user confirmed generated artifacts were removed and the working tree was clean.

## Gate 60 Validation Closure — COMPLETE

On 2026-10-14, the user confirmed the required PostgreSQL-focused tests, full PostgreSQL-backed suite, Ruff, diff check, and wheel build were clean and successful on main revision `080cc28ee38a207f3a5da83f36497510495a4a1a`.

## Gate 61 Validation Closure — COMPLETE

On 2026-10-14, the user confirmed all focused PostgreSQL migration/runtime privilege/API tests, the full PostgreSQL-backed suite, Ruff, diff check, and wheel build completed cleanly on main revision `0c6f22281f3242187ec2c1b3165b50557d9665d1`. No failures were reported.

## Gate 62 Validation Closure — COMPLETE

On 2026-10-14, the user confirmed Gate 62 was clean and successful on main revision `3b7d25914b1866a2c9617940970b2d08a44f8463`.

## Previous Gate Directive — Gate 63: Fail-Closed SECURITY DEFINER Routine Execution Verification — COMPLETE

Extend the read-only PostgreSQL runtime privilege verifier to reject any effective EXECUTE privilege on SECURITY DEFINER routines in the active application schema for either `current_user` or `session_user`, including inherited role and PUBLIC grants. Preserve ordinary invoker-security routine behavior, least-privilege application DML, audit append-only protections, migration-registry integrity, sequence checks, schema ownership checks, and the separate migration identity. Add a genuine PostgreSQL integration regression that creates an administrator-owned SECURITY DEFINER routine and proves a runtime login with EXECUTE privilege is rejected. Keep a least-privilege runtime role passing.

Inspect latest `main` before every cycle. Run focused PostgreSQL migration/runtime privilege/API tests, full `python -m pytest -q -rs` without skips, Ruff, diff check, and package wheel build. Fix blockers and remain on Gate 63 until the exact revision is user-validated. Maintain README.md, Architecture.md, MasterInstructions.md, and PROJECT_STATUS.md. All changes stay directly on `main`; no feature branches, no branch switching, no PR workflow, and no force pushes.


## Gate 63 Validation Closure — COMPLETE

The user confirmed Gate 63 clean and successful on 2026-10-14. Treat the SECURITY DEFINER execution verification gate as complete unless a regression is discovered.

## Previous Gate Directive — Gate 64: Authenticated SOC Workspace Read-Model Expansion — COMPLETE

Expose existing API-backed read models for campaigns, evidence, attack-path relationships, and administrator-only audit events in the authenticated dashboard. Use actual persisted API responses only. Preserve authorization boundaries, session-expiry behavior, evidence hashes, validation states, restrictive CSP, and existing overview behavior. Add regression assertions for the new sections and request paths. Run the UI tests, full PostgreSQL-backed suite without skips, Ruff, git diff --check, and package wheel build. Fix failures before advancing. Inspect latest main before every cycle; commit directly to main, with no branches, pull requests, or force pushes. After validation, reassess the next highest-priority unfinished architecture gap while keeping professional UI delivery moving.


## Gate 64 Validation Closure — COMPLETE

On 2026-10-14, the user confirmed Gate 64 clean and successful. The authenticated dashboard now surfaces existing campaign, evidence, attack-path relationship, and administrator-only audit read models. Commit: `ab4d354726f4d5cb4ab29b8b982ad64e96ec1f30`. This is recorded as user-confirmed validation; do not imply that local commands were independently run by the assistant.

## Previous Gate Directive — Gate 65: Professional SOC Workspace Navigation & Accessibility — COMPLETE

Keep active navigation synchronized with the visible section and set `aria-current` on the active item. Add visible keyboard focus indicators, honor reduced-motion preferences, and improve desktop navigation continuity without breaking mobile navigation. Preserve restrictive CSP, session-expiry behavior, same-origin API calls, API authorization, and persisted-only data rendering. Add UI regression assertions. Validate focused UI tests, full PostgreSQL-backed suite without skips, Ruff, `git diff --check`, and package wheel build. Fix blockers and remain on Gate 65 until exact-main validation is confirmed. Inspect latest `main` before every cycle; commit directly to `main`, with no branches, pull requests, or force pushes.


## Gate 65 Validation Closure — COMPLETE

On 2026-10-14, the user confirmed Gate 65 clean and successful. Treat the navigation/accessibility gate as complete unless a regression is discovered. This is user-confirmed validation; do not imply that local commands were independently run by the assistant.

## Current Gate Directive — Gate 66: Fail-Closed Runtime User-Identity Mutation Privilege Verification

Extend read-only PostgreSQL startup privilege verification to reject effective INSERT, UPDATE, or DELETE on the application-schema `users` table for `current_user` or `session_user`, including inherited and PUBLIC grants. Preserve SELECT for authentication, session lifecycle and rate-limit writes, audit append-only behavior, migration registry protections, existing ownership/DDL/sequence/SECURITY DEFINER checks, and the separate migration identity. Add real PostgreSQL integration regressions for each forbidden user-table mutation privilege and keep a least-privilege runtime role passing. Validate focused PostgreSQL privilege/migration/API tests, the full PostgreSQL-backed suite without skips, Ruff, `git diff --check`, and package wheel build. Fix blockers and remain on Gate 66 until exact-main validation is confirmed. Inspect latest `main` before every cycle; commit directly to `main`, with no branches, pull requests, or force pushes.
