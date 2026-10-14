# APM ThreatLens — Project Status

**Last updated:** 2026-10-14  
**Source of truth:** GitHub `main`  
**Highest architecture gate reached:** Gate 57  
**Highest fully validated gate:** Gate 56  
**Current gate:** Gate 57 — Fail-Closed Audit Protection Drift Detection  
**Current status:** Gate 57 implementation and final function-body hardening are committed directly to `main`; local validation of the latest revision is pending.

## Executive Summary

APM ThreatLens is an authorized VAPT orchestration platform with PostgreSQL persistence, authenticated scan lifecycle controls, controlled assessment providers, evidence-first handoff, finding correlation, risk assessment, attack-path analysis, evidence validation, remediation tracking, audit read models, and an initial authenticated dashboard.

Gates 49–51 remain complete based on prior user-confirmed validation. Gate 52's PostgreSQL execution-fence regression tests and Gate 53's API/PostgreSQL remediation-idempotency tests were confirmed executed successfully on 2026-10-14: the full suite reached 100% without a skip summary, focused remediation tests passed (9 API tests and 5 PostgreSQL tests), Ruff passed, diff checks were clean, and the package wheel built successfully. Five Starlette deprecation warnings remain non-blocking.

## Completed Gate 54 — Versioned PostgreSQL Schema Migrations

The versioned migration registry is active. Startup uses a stable PostgreSQL session advisory lock, validates ordered version/name/checksum history, adopts pre-versioned installations through the retry-safe legacy baseline, and records transactional migrations atomically. Startup fails closed on unknown future versions, history gaps, and identity/checksum drift.

**Validation closure:** On 2026-10-14, the user confirmed 3 focused migration tests, 14 focused remediation API/PostgreSQL tests, the full PostgreSQL-backed suite at 100% with no skip summary, Ruff, diff checks, and wheel build all passed on `f0f4d543947f864ff05d6e7173839b105562cd2c`. Five Starlette deprecation warnings were non-failing.

## Completed Gate 55 — Database-Enforced Append-Only Security Audit Trail

Migration version 2, `audit_events_append_only`, installs a PostgreSQL trigger rejecting UPDATE and DELETE on `audit_events` with SQLSTATE `55000`, while preserving normal inserts and existing audit rows.

**Validation closure:** On 2026-10-14, the user confirmed 4 focused migration tests, 14 focused remediation API/PostgreSQL tests, the full PostgreSQL-backed suite with no skip summary, Ruff, diff checks, and wheel build passed on `8dcb6974132713bf426b30bfc202260c9a5ff699`. Five Starlette deprecation warnings were non-failing.

## Completed Gate 56 — PostgreSQL Audit Trail Truncation Protection

Migration version 3 adds a statement-level `BEFORE TRUNCATE` trigger to complement the row-level UPDATE/DELETE protection from Gate 55. The user confirmed 4 focused migration tests, 14 focused remediation tests, the full PostgreSQL-backed suite at 100% without a skip summary, Ruff, diff checks, and wheel build on commit `4e96495a5ee85e23b35033f364f379120898d159`. Five Starlette deprecation warnings were non-failing. Database owners/superusers able to disable triggers or alter schema remain outside this control's threat boundary.

## Current Gate 57 — Fail-Closed Audit Protection Drift Detection

### Objective and root cause

Migration history does not prove that audit-protection triggers remain installed and enabled after deployment. If a trigger is disabled or dropped while the migration registry remains unchanged, startup could otherwise continue without the intended database control.

### Implementation on main

- Added startup verification for both audit-protection triggers using PostgreSQL catalog trigger-type bits, checking presence, enabled state, expected event/row-or-statement semantics, and the fail-closed trigger function.
- Added PostgreSQL integration regressions proving initialization rejects a disabled or missing truncation trigger and succeeds after restoration.
- Updated README.md, Architecture.md, MasterInstructions.md, and this status report to close Gate 56 and identify Gate 57 as active.

### Validation

The initial Gate 57 focused run failed because the verifier assumed a fixed textual ordering for UPDATE/DELETE in PostgreSQL's trigger definition. The verifier was changed to inspect catalog trigger-type bits, and missing-trigger coverage was added. The six focused migration tests passed on the pre-fix revision, but the broader run then exposed lock contention: one connection remained idle in transaction holding AccessExclusive relation locks while a second connection's authentication SELECT waited on the users table.

Root cause: the catalog SELECT in _verify_audit_protection() started a new implicit psycopg transaction after run_migrations() had committed and released its migration lock. The integration fixture's transaction context then nested as a savepoint, leaving its trigger changes and TRUNCATE locks held after RELEASE. The migration runner now commits after successful verification and rolls back if verification raises. Regression tests assert the connection returns to IDLE after successful verification and after fail-closed disabled/missing-trigger errors. Fix commits: `db4d3a6a3b602b4227b7abb6b04f8e646567b3ec` and `9777d2b201941de4c3f012246a39303ba0cf5057`.

**Validation update:** The user confirmed the previous revision `fa3915a423bb9e3cc78fa7628f535c1faa45dee0` passed focused migration tests (7), broader PostgreSQL tests (23), the isolated cross-instance idempotency test (1), the full pytest suite without a skip summary, Ruff, diff checks, and wheel build. Final security re-inspection found that marker-string checks could miss an altered trigger-function body. The verifier now compares normalized function source against the expected unconditional fail-closed implementation, and a PostgreSQL regression test exercises weakened function behavior. The hardening is committed directly to `main`; run focused migration tests, the full PostgreSQL-backed suite, Ruff, diff checks, and wheel build on the latest main SHA before completing Gate 57.

## Recent Completed Gates

| Gate | Improvement | Status |
|---|---|---|
| 49 | Durable cross-instance scan-queue idempotency; replay returns original execution, conflicting key reuse rejected | Complete — user-confirmed validation |
| 50 | Durable idempotency for cancellation and stale-recovery commands; atomic command result and audit | Complete — user-confirmed validation |
| 51 | Fail-closed heartbeat lease handling, cooperative cancellation on lease loss, and heartbeat-worker shutdown | Complete — user-confirmed validation |
| 52 | Execution-lease-fenced evidence/finding persistence and fail-closed compatibility behavior | Complete — PostgreSQL-backed tests executed and user-confirmed on 2026-10-14 |

## Broader Capability Improvements Recorded in Repository

- PostgreSQL is the canonical production and active integration-test persistence path.
- Authenticated application APIs for campaign/scope control, scan lifecycle control, findings, evidence, risk assessments, attack-path relationships/analysis, and security audit read models.
- Cross-instance scan command idempotency and retry/recovery serialization.
- Durable heartbeat leases, stale recovery, lifecycle compare-and-set transitions, bounded provider concurrency, and atomic audit/lifecycle writes.
- Controlled discovery, TCP service discovery/interrogation, TLS, web, and API assessment providers with explicit scope and bounded behavior.
- Evidence sealing with SHA-256, provenance-aware handoff, durable finding correlation, vulnerability intelligence normalization/matching, and context-aware correlation.
- Risk assessment and validated evidence-backed attack-path analysis.
- Initial authenticated, read-only dashboard UI with restrictive response security headers.

## Feedback and Recommendations

1. Run `python -m pytest -q -rs` and confirm the PostgreSQL-backed execution-fence regression tests were not skipped.
2. Keep generated Python bytecode/build artifacts out of commits. The repository currently tracks some `.pyc` files, so tests may modify them; clean them before checking final Git status.
3. Consider a dedicated follow-up cleanup to stop tracking generated `__pycache__`/`.pyc` artifacts and add/verify ignore rules. Do not mix that cleanup into Gate 52 unless it is necessary to validate this gate.
4. After Gate 52's required PostgreSQL-backed tests are confirmed executed, re-fetch latest `main`, inspect the architecture and implementation, and select the next highest-priority unfinished gap.


## Gate 52 and Gate 53 Validation Closure

### Gate 52 — Execution-Lease-Fenced Evidence and Finding Persistence — COMPLETE

On 2026-10-14, the user confirmed the PostgreSQL-backed full test suite completed at 100% with no skip summary, along with clean Ruff and diff checks and a successful package wheel build. The run included the PostgreSQL integration tests, resolving the prior skip-review blocker.

### Gate 53 — Durable Finding Remediation Idempotency — COMPLETE

On 2026-10-14, the user confirmed 9 focused API tests and 5 focused PostgreSQL remediation tests passed. The full test suite reached 100%, Ruff and diff checks were clean, and the package wheel built successfully.

The five Starlette deprecation warnings about `HTTP_422_UNPROCESSABLE_ENTITY` were non-failing warnings.

## Next Required Action

Validate Gate 57 against the exact current `main` revision using `python -m pytest -q tests/test_postgres_schema_migrations.py`, `python -m pytest -q -rs`, `ruff check .`, `git diff --check`, and `python -m pip wheel . --no-deps --wheel-dir /tmp/apm-threatlens-wheel`. Confirm PostgreSQL integration tests execute and do not skip. If any check fails, fix it and remain on Gate 57.
