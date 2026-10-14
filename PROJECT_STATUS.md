# APM ThreatLens — Project Status

**Last updated:** 2026-10-14  
**Source of truth:** GitHub `main`  
**Highest architecture gate reached:** Gate 63  
**Highest fully validated gate:** Gate 62  
**Current gate:** Gate 63 — Fail-Closed SECURITY DEFINER Routine Execution Verification  
**Current status:** Gate 62 was confirmed clean and successful by the user on 2026-10-14 at main revision `3b7d25914b1866a2c9617940970b2d08a44f8463`. Gate 63 implementation is committed directly to `main`; exact-revision validation is pending.

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

## Completed Gate 57 — Fail-Closed Audit Protection Drift Detection

### Objective and root cause

Migration history does not prove that audit-protection triggers remain installed and enabled after deployment. If a trigger is disabled or dropped while the migration registry remains unchanged, startup could otherwise continue without the intended database control.

### Implementation on main

- Added startup verification for both audit-protection triggers using PostgreSQL catalog trigger-type bits, checking presence, enabled state, expected event/row-or-statement semantics, and the fail-closed trigger function.
- Added PostgreSQL integration regressions proving initialization rejects a disabled or missing truncation trigger and succeeds after restoration.
- Updated README.md, Architecture.md, MasterInstructions.md, and this status report to close Gate 56 and identify Gate 57 as active.

### Validation

The initial Gate 57 focused run failed because the verifier assumed a fixed textual ordering for UPDATE/DELETE in PostgreSQL's trigger definition. The verifier was changed to inspect catalog trigger-type bits, and missing-trigger coverage was added. The six focused migration tests passed on the pre-fix revision, but the broader run then exposed lock contention: one connection remained idle in transaction holding AccessExclusive relation locks while a second connection's authentication SELECT waited on the users table.

Root cause: the catalog SELECT in _verify_audit_protection() started a new implicit psycopg transaction after run_migrations() had committed and released its migration lock. The integration fixture's transaction context then nested as a savepoint, leaving its trigger changes and TRUNCATE locks held after RELEASE. The migration runner now commits after successful verification and rolls back if verification raises. Regression tests assert the connection returns to IDLE after successful verification and after fail-closed disabled/missing-trigger errors. Fix commits: `db4d3a6a3b602b4227b7abb6b04f8e646567b3ec` and `9777d2b201941de4c3f012246a39303ba0cf5057`.

**Validation update:** The user confirmed the previous revision `fa3915a423bb9e3cc78fa7628f535c1faa45dee0` passed focused migration tests (7), broader PostgreSQL tests (23), the isolated cross-instance idempotency test (1), the full pytest suite without a skip summary, Ruff, diff checks, and wheel build. Final security re-inspection found that marker-string checks could miss an altered trigger-function body. The verifier now compares normalized function source against the expected unconditional fail-closed implementation, and a PostgreSQL regression test exercises weakened function behavior. The hardening is committed directly to `main`. On 2026-10-14, the user confirmed the final revision `db3b98165bb10351cb3fc2b10de964c44a5dcd90` passed all 8 PostgreSQL schema migration tests, the full pytest suite without a skip summary, Ruff, diff checks, and package wheel build. The hardened wheel SHA-256 was `b981c440324ff82895baf5bd5d20ca6b5f421ee20debdf98a40a561f316a5ed2`. Five Starlette deprecation warnings were non-blocking.

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

## Gate 58 — PostgreSQL Runtime/Migration Privilege Separation — COMPLETE

### Root cause
API startup previously ran `PostgresRepository.initialize()` using the runtime DSN. That placed migration DDL authority in the normal API process and weakened the audit-trigger boundary against compromise of the runtime identity.

### Implementation
- Added read-only `verify_schema_ready()` to check the ordered migration registry and audit-protection invariants.
- Changed API startup to verify readiness without applying DDL; readiness failure closes the runtime connection and fails startup.
- Added `python -m threatlens.storage.migrate`, requiring `THREATLENS_MIGRATION_DATABASE_URL` and closing its connection after migration.
- Added PostgreSQL role-privilege integration coverage and API factory tests.
- Updated `.env.example` and deployment guidance for separate runtime/migration DSNs and restricted audit/registry grants.

### Validation closure
On 2026-10-14, the user confirmed validation on exact main commit `c39a7cd9d757e2a63cc27365e6e2b8e8a5e529b3`:
- Focused migration, runtime-privilege, and API tests: **37 passed**.
- Full `python -m pytest -q -rs`: completed at 100%, with no skip summary and no reported failures.
- `ruff check .`: passed.
- `git diff --check`: clean.
- Wheel build: passed; SHA-256 `6867d9542088c520678beee241b1fd26ebc0fb73885ea6f4c16bbc5f4bf1fb25`.
- Five Starlette deprecation warnings were non-failing.
- `HEAD` matched `origin/main`; working tree was clean after removing only `build/` and `src/apm_threatlens.egg-info/`.

### Security review
API startup no longer applies schema migrations. The test suite demonstrates a non-owner runtime role cannot disable/drop audit triggers or replace their function, and cannot mutate protected audit/migration-registry rows. Production deployment must still provision roles with correct ownership and effective grants.

## Gate 59 — Fail-Closed Runtime Database Privilege Verification — COMPLETE

### Root cause
Gate 58 separates migration and runtime DSNs, but the API could still be configured with a superuser, database/schema owner, or role inheriting unsafe DDL privileges. Schema readiness and audit-trigger verification alone do not establish that the effective API identity is least-privileged.

### Implementation
- Added `verify_runtime_privileges()` to inspect both `current_user` and `session_user`.
- Fails closed for superuser identities; effective database/schema CREATE privileges; audit UPDATE/DELETE/TRUNCATE/TRIGGER privileges; migration registry INSERT/UPDATE/DELETE/TRUNCATE privileges; and membership in database, schema, table, or trigger-function owning roles.
- API startup runs the check after read-only schema readiness verification and closes the connection on any startup failure.
- Added PostgreSQL integration coverage for least-privilege login, direct schema CREATE, inherited DDL role membership, explicit audit-table UPDATE and migration-registry UPDATE rejection, and API cleanup after privilege-verification failure.
- Implementation commits on `main`: verifier `b0376c5` (hardened in `e387355`, `415c3db`, `2f63434`, and `fb965a7`), repository method `2233ceb`, API enforcement `df9c541`, PostgreSQL integration tests `7881afa`, `0bf8a82`, and helper formatting `6fea147`, API startup tests `4c35909` and `0743d97`, documentation updates `7d375b7`, `42fc76d`, `c8e2861`, `64655b2`, `5383aca`, `8c30e17`, `295640d`, and this status update. All commits are direct-to-main.
- All changes are committed directly to `main`; no feature branches or pull requests.

### Validation closure
On 2026-10-14, the user confirmed exact-main revision `78f7856677d029c2f01d0000831b080e16c8f45c` passed 43 focused PostgreSQL migration/runtime-privilege/API tests, the full PostgreSQL-backed suite reached 100% without a reported failure or skip summary, `ruff check .`, `git diff --check`, and package wheel build. Wheel SHA-256: `f5315fe6366d53d9607e11aa1f4624978266c3e29a75376377bd17d03d63bb71`. Five Starlette deprecation warnings were non-failing. The user confirmed generated `build/` and `src/apm_threatlens.egg-info/` artifacts were removed and the working tree was clean.

## Gate 60 — Fail-Closed Runtime Ownership Boundary for Application Schema Objects — COMPLETE

### Root cause
Gate 59 verifies ownership/membership for the database, active schema, audit table, migration registry, and audit trigger function. It does not enumerate all application-schema relations, routines, or types. A runtime login that owns another application object may still possess destructive DDL authority over that object.

### Implementation
- Extended the existing runtime startup verifier to detect relations, routines, and types in the active application schema owned by `current_user`, `session_user`, or any role inherited by either identity.
- Fails closed with a safe diagnostic when any application-schema object is runtime-owned.
- Added PostgreSQL integration coverage using a genuine temporary login that owns an application-schema table.
- Preserved read-only API startup and the separate migration identity.
- Updated README.md, Architecture.md, MasterInstructions.md, and PROJECT_STATUS.md directly on `main`.
- Implementation and documentation commit: `eb9670bbdfe8552759588efe6f61d44b72ebbb8f`.
- PostgreSQL test fixture refinement (creates the owned table through the actual runtime login, then revokes schema CREATE): `52776227a15b28301286be0db2339064a13c7354`.

### Validation closure
On 2026-10-14, the user confirmed the required PostgreSQL-focused tests, full PostgreSQL-backed suite, Ruff, diff check, and wheel build were clean and successful on main revision `080cc28ee38a207f3a5da83f36497510495a4a1a`. No failures were reported.

## Gate 61 — Fail-Closed Runtime Relation Privilege Verification — COMPLETE

### Root cause
Gate 60 blocks runtime ownership but does not detect high-impact relation ACLs granted to non-owner roles. TRUNCATE can erase a table without row-by-row DELETE behavior; TRIGGER and REFERENCES allow structural capabilities that the runtime application does not need.

### Implementation
- Extended the existing read-only runtime verifier to inspect ordinary and partitioned tables in the active application schema.
- Rejects effective TRUNCATE, TRIGGER, or REFERENCES privileges granted to `current_user`, `session_user`, or inherited roles.
- Added PostgreSQL-backed parameterized regressions granting each privilege separately on the ordinary `assets` table.
- Preserved normal application DML, Gate 58 migration separation, and Gate 59/60 protections.
- Updated README.md, Architecture.md, MasterInstructions.md, and PROJECT_STATUS.md directly on `main`.
- Gate 61 implementation commit: `7c297c8f5084a48674106eb4392c4c2536546b62`.

### Validation closure
On 2026-10-14, the user confirmed all focused PostgreSQL migration/runtime privilege/API tests, the full PostgreSQL-backed suite, Ruff, diff check, and wheel build completed cleanly on main revision `0c6f22281f3242187ec2c1b3165b50557d9665d1`. No failures were reported.

## Gate 62 — Fail-Closed Runtime Sequence Privilege Verification — COMPLETE

### Root cause
Gate 61 checks destructive/structural privileges on application tables but does not inspect application-schema sequence ACLs. Sequence UPDATE permits `setval`, and USAGE permits `nextval`; neither is needed for UUID-backed runtime identifiers. SELECT is likewise unnecessary under the current storage contract.

### Implementation
- Extended read-only startup verification to inspect all application-schema sequences.
- Rejects effective SELECT, USAGE, and UPDATE sequence privileges for `current_user`, `session_user`, or inherited roles.
- Added PostgreSQL-backed regressions that grant each privilege separately on an administrator-owned sequence to a genuine runtime login.
- Preserved the least-privilege runtime path, audit/migration protections, and controlled migration identity.
- Updated README.md, Architecture.md, MasterInstructions.md, and PROJECT_STATUS.md directly on `main`.
- Gate 62 implementation commit: `2a460554fbb39442af867ce691625e33b3d60c9f`.

### Validation closure
On 2026-10-14, the user confirmed Gate 62 was clean and successful on main revision `3b7d25914b1866a2c9617940970b2d08a44f8463`.


## Gate 63 — Fail-Closed SECURITY DEFINER Routine Execution Verification — IMPLEMENTED, VALIDATION PENDING

### Root cause
The existing verifier blocks runtime ownership of routines and checks sequence and table privileges, but it did not inspect whether the runtime identity could execute a SECURITY DEFINER routine. Such a routine runs with its owner's privileges and can become an escalation path even when the runtime login does not own the routine.

### Implementation
- Extended the read-only runtime verifier to enumerate SECURITY DEFINER routines in the active application schema and detect effective EXECUTE privilege for `current_user` or `session_user`, including inherited and PUBLIC grants.
- Added a PostgreSQL integration regression that creates a SECURITY DEFINER routine, grants EXECUTE to a real runtime login, and expects fail-closed rejection.
- Preserved invoker-security routines, UUID/sequence controls, audit and migration-registry protection, and separate migration identity.
- Updated README.md, Architecture.md, MasterInstructions.md, and PROJECT_STATUS.md directly on `main`.
- Implementation commits: verifier `4d9c305e060b783b7dafe07c56dd469042abaf50`; integration test `32c88d0fd8839c0da173c48c41dd07ae5d9f2181`.

### Validation required
Run focused PostgreSQL migration/runtime privilege/API tests, the full PostgreSQL-backed `python -m pytest -q -rs` suite without skips, `ruff check .`, `git diff --check`, and package wheel build on the exact latest `main` SHA. Fix any failure before moving on. Do not claim Gate 63 validated until the user confirms exact-revision results.

## Next Required Action

Validate Gate 63 on the latest `main`, including the SECURITY DEFINER execution regression and the existing least-privilege runtime role test.
