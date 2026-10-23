# APM ThreatLens — Project Status

**Last updated:** 2026-10-23
**Source of truth:** GitHub `main`  
**Highest architecture gate reached:** Gate 90
**Highest fully validated gate:** Gate 90 (user-confirmed on 2026-10-23)
**Current gate:** Gate 91 - determine from the highest unfinished architecture gap on main
**Current status:** Gate 90 implementation is committed and pushed on `main` at `2b26748`. Focused Web/API tests and the full pytest suite reached 100%; the full run exited 0. Ruff and `git diff --check` passed. Windows wheel build succeeded with SHA-256 `750799068f195d4908e613fb26790eb19669eea52f4082576f6bac2dfe443acd`. Six Starlette deprecation warnings were non-failing; the captured summary did not include explicit passed/skipped totals.

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


## Gate 63 — Fail-Closed SECURITY DEFINER Routine Execution Verification — COMPLETE

### Root cause
The existing verifier blocks runtime ownership of routines and checks sequence and table privileges, but it did not inspect whether the runtime identity could execute a SECURITY DEFINER routine. Such a routine runs with its owner's privileges and can become an escalation path even when the runtime login does not own the routine.

### Implementation
- Extended the read-only runtime verifier to enumerate SECURITY DEFINER routines in the active application schema and detect effective EXECUTE privilege for `current_user` or `session_user`, including inherited and PUBLIC grants.
- Added a PostgreSQL integration regression that creates a SECURITY DEFINER routine, grants EXECUTE to a real runtime login, and expects fail-closed rejection.
- Preserved invoker-security routines, UUID/sequence controls, audit and migration-registry protection, and separate migration identity.
- Updated README.md, Architecture.md, MasterInstructions.md, and PROJECT_STATUS.md directly on `main`.
- Implementation commits: verifier `4d9c305e060b783b7dafe07c56dd469042abaf50`; integration test `32c88d0fd8839c0da173c48c41dd07ae5d9f2181`.

### Validation closure
On 2026-10-14, the user confirmed the PostgreSQL security/migration/API tests, full PostgreSQL-backed suite, Ruff, diff check, and wheel build were clean. This confirmation closes Gate 63.

## Gate 64 — Authenticated SOC Workspace Read-Model Expansion — COMPLETE

### Root cause
The authenticated dashboard did not expose existing campaign, evidence, attack-path relationship, and administrator-only audit-event read models.

### Implementation
- Added dashboard sections for campaigns, evidence, attack-path relationships, and administrator-only audit events.
- Loaded only persisted records through the existing authenticated API contracts.
- Preserved evidence SHA-256 values, relationship validation state, and safe handling of non-admin audit access.
- Added dashboard markup/API-path regression assertions.
- Updated README.md, Architecture.md, MasterInstructions.md, and PROJECT_STATUS.md directly on `main`.
- Commit: `ab4d354726f4d5cb4ab29b8b982ad64e96ec1f30`.

### Validation closure
On 2026-10-14, the user confirmed Gate 64 was clean and successful. This is recorded as user-confirmed validation; the assistant did not independently execute the local test, lint, PostgreSQL suite, or wheel-build commands in this environment.

## Gate 65 — Professional SOC Workspace Navigation & Accessibility — COMPLETE

### Root cause
The new workspace sections are reachable through anchor links, but the active navigation state only changes on click and can become inaccurate when users scroll manually. The UI also lacks explicit keyboard focus styling and reduced-motion handling, which weakens predictable navigation and accessibility.

### Acceptance criteria
- Keep the active navigation item synchronized with the currently visible workspace section and expose it using `aria-current`.
- Improve desktop navigation continuity without making the mobile navigation unusable.
- Provide visible keyboard focus indicators for links, buttons, and form controls.
- Respect the user's reduced-motion preference.
- Add static UI regression assertions for navigation state and accessibility styling.
- Preserve same-origin API calls, session handling, CSP compatibility, API authorization, and persisted-only data rendering.
- Validate focused UI tests, full PostgreSQL-backed suite without skips, Ruff, diff checks, and package wheel build before closing the gate.

### Validation closure

On 2026-10-14, the user confirmed Gate 65 clean and successful on main. This is recorded as user-confirmed validation; the assistant did not independently execute local UI tests, full PostgreSQL suite, Ruff, or wheel build.

## Gate 66 — Fail-Closed Runtime User-Identity Mutation Privilege Verification — COMPLETE

### Root cause and implementation
The runtime privilege verifier rejects effective table-level INSERT, UPDATE, or DELETE on the authentication `users` table. These rights are not required by runtime authentication; provisioning belongs to a trusted deployment/admin workflow.

- Added effective user-table mutation checks for both `current_user` and `session_user`, including inherited/PUBLIC grants through PostgreSQL privilege functions.
- Added real PostgreSQL regressions for INSERT, UPDATE, and DELETE grants while preserving the least-privilege runtime role.
- Updated README.md, Architecture.md, MasterInstructions.md, and PROJECT_STATUS.md.

**Validation closure:** On 2026-10-14, the user confirmed Gate 66 clean and successful. This is user-confirmed validation; the assistant did not independently execute the local test, PostgreSQL, lint, or wheel-build commands in this environment.

## Gate 67 — Fail-Closed Runtime Column-Level User-Identity Mutation Privilege Verification — COMPLETE

### Root cause and implementation
PostgreSQL supports column-level INSERT and UPDATE grants that are not reliably covered by table-level privilege checks alone.

- Added effective `has_any_column_privilege` checks for both `current_user` and `session_user`.
- Added PostgreSQL integration regressions for column-level INSERT and UPDATE grants to sensitive user columns.
- Updated README.md, Architecture.md, MasterInstructions.md, and PROJECT_STATUS.md.

**Validation closure:** On 2026-10-14, the user confirmed Gate 67 clean and successful. This is user-confirmed validation; the assistant did not independently execute the local test, PostgreSQL, lint, or wheel-build commands in this environment.

## Gate 68 — Fail-Closed Handling of Invalid Persisted User Roles — COMPLETE

### Root cause
The authentication service converts stored role values into the fixed `Role` enum in login and session-authentication paths. A malformed or unsupported persisted role could otherwise escape as an unhandled `ValueError`.

### Implementation
- Invalid persisted roles now follow the existing fail-closed authentication/session error paths.
- Login records a denied audit event with fixed generic detail `invalid stored role`, creates no session, and does not disclose the stored value.
- Existing sessions fail closed if the associated user's persisted role is invalid.
- Added regression tests for both login and session authentication.
- Updated README.md, Architecture.md, MasterInstructions.md, and PROJECT_STATUS.md.

**Validation closure:** On 2026-10-14, the user confirmed Gate 68 clean and successful. This is user-confirmed validation; the assistant did not independently execute local test, PostgreSQL, lint, diff-check, or wheel-build commands in this environment.

## Gate 69 — Fail-Closed Handling of Corrupt Persisted Session Records — COMPLETE

### Implementation
- Malformed persisted expiry timestamps and session/user UUID identifiers fail closed through the generic invalid-session error.
- Preserved explicit inactive-user behavior and infrastructure exception propagation.
- Added regression tests for corrupted persisted session records.

**Validation closure:** On 2026-10-14, the user confirmed Gate 69 clean and successful. This is user-confirmed validation; the assistant did not independently execute local test, PostgreSQL, lint, diff-check, or wheel-build commands in this environment.

## Gate 70 — Atomic Login Session and Success-Audit Persistence — COMPLETE

### Root cause
Successful login previously committed the authentication session and success audit event through separate repository calls, allowing an active session to remain after audit insertion failure.

### Implementation
- Added atomic session-plus-success-audit persistence to SQLite and PostgreSQL repositories.
- Routed successful login through the atomic repository operation.
- Added audit-failure rollback regressions and repaired repository test doubles to implement the atomic contract.
- Preserved denied-login auditing, password verification, active-user/role checks, session expiry/revocation, and append-only audit protection.

### Validation closure
On 2026-10-14, the user confirmed focused API tests, the full PostgreSQL-backed pytest suite, Ruff, `git diff --check`, package wheel build, and final main synchronization were clean. Five Starlette deprecation warnings were non-failing. The optional `python -m build` command was unavailable because the module was not installed; the established pip wheel build was used instead. This is user-confirmed validation.

## Gate 71 — Atomic Logout Session Revocation and Success-Audit Persistence — COMPLETE

### Root cause
`AuthenticationService.logout()` previously invoked `revoke_session()` and `save_audit_event()` as separate persistence operations. If audit insertion failed after revocation committed, the session was revoked while the caller received a failure and the corresponding successful logout event was absent.

### Implementation
- Added `revoke_session_with_audit()` to the SQLite and PostgreSQL authentication storage mixins.
- The operation updates session revocation and inserts the LOGOUT success audit event inside one transaction; PostgreSQL also serializes the operation with the repository transaction lock.
- Routed `AuthenticationService.logout()` through the atomic operation.
- Added SQLite and PostgreSQL failure-injection regressions and updated the API test double to implement the atomic logout contract.

### Validation closure
On 2026-10-14, the user confirmed Gate 71 clean and successful. This is user-confirmed validation; the assistant did not independently execute local test, PostgreSQL, lint, diff-check, or wheel-build commands.


## Gate 72 — Atomic User Provisioning and Success-Audit Persistence — COMPLETE

### Root cause
`AuthenticationService.create_user()` previously committed the user row through `save_user()` and then separately inserted the USER_CREATED success audit event. An audit-write failure could leave a provisioned account without its corresponding success audit event.

### Implementation on main
- Added `save_user_with_audit()` to the SQLite compatibility and PostgreSQL authentication storage mixins.
- The new operation inserts the user and USER_CREATED success event in one transaction; PostgreSQL also uses the repository transaction lock.
- Routed `AuthenticationService.create_user()` through the atomic repository operation.
- Added SQLite and PostgreSQL failure-injection regressions proving audit failure rolls back user creation and successful retry persists both records.
- Updated the API test double to implement the atomic user-provisioning contract.
- Updated README.md, Architecture.md, MasterInstructions.md, and this status report directly on `main`.

### Pytest failure and corrective change
The uploaded full-suite log showed repeated `AttributeError: 'FakeRepository' object has no attribute 'save_user_with_audit'` failures. Gate 72 changed `AuthenticationService.create_user()` to require the atomic repository operation, but several API-test fakes still implemented only `save_user()`. Updated the fakes in scan-control, scan-queue, evidence read model, evidence validation, finding remediation, risk assessment, risk-assessment read model, attack-path relations, and campaign-control tests. Each fake now rolls back its in-memory user/audit state if audit persistence raises. Commits are on `main`; latest corrective commits include `9284cb387813fada3ef05b0c0edfa520b236c584`, `417479b19ba389b46e41b45103c0008bc42c0f6e`, `09b0d617582eb2f2ac702777ec4cf6e045bce3bd`, `ddbef9e128af973a9033dd32d3525380e2ccb258`, `6c0fcae6df1a5fe43f8ddb86598fee74de60afec`, `e63cd4f13b1cce3eec36693a93fdd0a60b2c2984`, and `4812361b4b1138b5ed6028d4b1ef3d701b5a0bac`.

### Lint blocker correction
Ruff subsequently found `F821 Undefined name User` in `tests/test_api_attack_path_relations.py`: the Gate 72 fake repository annotated `save_user_with_audit()` with `User` but the module did not import it. Added `User` to the existing `threatlens.domain.models` import directly on `main` in commit `cb61cf8cbb63f0fb3456da202957243215e2b9d0`. This lint blocker was corrected in commit `cb61cf8cbb63f0fb3456da202957243215e2b9d0`; the final Ruff and full-suite validation subsequently passed as recorded in the validation closure below.

### Validation closure — COMPLETE

On 2026-10-19, the user confirmed the dedicated PostgreSQL test database was `threatlens_gate72_test`. Focused authentication/storage validation passed: **20 passed**, including `test_postgres_user_creation_and_success_audit_are_atomic`, `test_user_creation_and_success_audit_are_atomic_on_audit_failure`, and the PostgreSQL logout atomicity regression. The full PostgreSQL-backed suite then passed with **309 passed, 0 skipped, 5 non-failing Starlette deprecation warnings**. `ruff check .` reported all checks passed; `git diff --check` was clean; and `python -m pip wheel . --no-deps --wheel-dir /tmp/apm-threatlens-wheel` successfully built `apm_threatlens-0.1.0-py3-none-any.whl` (SHA-256 `eb66201f4e2622b35d262e399e12df464b58b014011be7ab54ac167575e98f49`). Validation is user-confirmed from terminal output, not independently executed by the assistant.

Gate 72 is complete. Before the next implementation gate, fetch and inspect the latest `main`, review the governing architecture documents and relevant code, identify the highest-priority unfinished architecture gap, and state the acceptance criteria before making a surgical change. Continue committing directly to `main`; no branches, pull requests, branch switching, or force pushes.

## Gate 73 — Atomic Login Rate-Limit Threshold Audit Persistence — IN PROGRESS

### Root cause

The API previously incremented durable login-attempt buckets in one repository transaction, then separately inserted `LOGIN_RATE_LIMITED` audit events after observing the threshold crossing. An audit insert failure could leave the rate-limit counter committed without its corresponding threshold-crossing audit record.

### Bounded implementation scope

- Extend the PostgreSQL login-attempt operation with optional threshold metadata and insert only threshold-crossing audit events in the same transaction as bucket updates.
- Pass client and client/username thresholds from the login API; remove the separate post-transaction audit write.
- Preserve privacy-preserving hashed bucket keys, the existing 30-attempt client and 5-attempt identity limits, the 60-second window, Retry-After behavior, and threshold-crossing-only audit volume.
- Add API regression coverage for one threshold event across repeated blocked retries and PostgreSQL failure-injection coverage proving a failed audit insert rolls back the corresponding counter increment.

### Acceptance criteria

1. Threshold-crossing counter changes and the corresponding audit event commit or roll back together.
2. Repeated blocked attempts do not create an audit event for every request.
3. Existing rate-limit and authentication behavior remains unchanged when persistence succeeds.
4. Focused PostgreSQL and API tests, full PostgreSQL-backed `python -m pytest -q -rs` with no skips, `ruff check .`, `git diff --check`, and `python -m pip wheel . --no-deps --wheel-dir /tmp/apm-threatlens-wheel` pass on the exact `main` revision.

### Changed files and main commits

- `src/threatlens/storage/auth.py` — atomic counter/audit transaction: `930b10ee10f70f86ab81b6509f09b340e9bf2536`
- `src/threatlens/api/app.py` — pass thresholds to repository; remove separate audit write: `2a0e9a17c4a4ce1452855bbd53a6c1559ee8d8ab`
- `tests/test_api_app.py` — threshold audit assertion and fake repository transaction behavior: `9188bbd85a8402c1a01fcc68cf7abfe15901f3af`, `b42bf08165d0077602aee749ff03e74e3b8bd47b`, `1c5186146e23938a472fe0b4f44390e4710e28be`
- `tests/test_auth_storage.py` — PostgreSQL failure-injection regression and trigger quoting correction: `10750ad70ee193c0c951c3d4ddd7eca33f9cd396`, `c2eb06be9d418c3cb3c36c49a482a5a2d2b8348e`, `36276c7a0605cc74e64cb5a7800e533b3a64e077`
- Governing documentation updated directly on `main`: `3f8b1463a4155a8edb4f7e41e4dffd451b9f7b6e`, `d4f8db5f7dcc002ecc2f2f924e431a59efbea3a7`, `524be433bf4fcd22d0c05dc34a0f3ba3c452f918`, `402434f069ee938b6586dd52e32a378f235e3845`

### Validation closure — COMPLETE

On 2026-10-21, the user confirmed focused PostgreSQL/API tests and the full PostgreSQL-backed `pytest -q -rs` suite passed in the Windows Python 3.15 environment. Ruff and `git diff --check` passed. `pip wheel` successfully built `apm_threatlens-0.1.0-py3-none-any.whl` (SHA-256 `ae82526e8bffef66a9e426f99ff20a2c5199091579aa32b644273a7bc234a565`). Five Starlette deprecation warnings were non-failing. Validation was user-run and user-confirmed. The unused-import cleanup and status documentation are local changes awaiting the user's normal VS Code/GitHub sync; no push was performed.

## Gate 74 — Python 3.15 Windows Dependency-Install Compatibility — COMPLETE

A clean Python 3.15 Windows install of the previous `uvicorn[standard]` dependency chain attempted to build PyYAML from source and failed when Microsoft C++ Build Tools were unavailable. The dependency now uses Uvicorn core; repository inspection found no use of the optional extras' YAML config, reload, or alternative HTTP/WebSocket implementations.

### Validation closure — COMPLETE

On 2026-10-21, a clean Python 3.15 dependency install built and installed the project successfully. Imports passed in an isolated environment with PyYAML absent. Ruff and `git diff --check` passed. The user confirmed the full PostgreSQL-backed `pytest -q -rs` suite passed with no skip summary; five Starlette deprecation warnings were non-failing. Validation is user-confirmed. No commit or push was made.

## Gate 75 — Evidence-Backed Campaign Report Export — COMPLETE

### Root cause

The project had authenticated global read models for campaigns, findings, scans, risk, and evidence, but no campaign-scoped report contract or export. A report assembled only from global paginated read models could mix campaign data or omit records.

### Bounded implementation

- Add a PostgreSQL report read model that associates findings only through evidence provenance whose execution IDs belong to the requested campaign.
- Return campaign scope, scan counts, finding counts/details, latest persisted risk, and campaign-scoped evidence references. Never return raw evidence payloads.
- Bound output to 500 findings and 20 evidence references per finding and mark truncation explicitly.
- Add an authenticated JSON attachment endpoint and a dashboard campaign selector/download action.

### Validation state

### Changed files

- `src/threatlens/storage/postgres.py` — campaign-filtered report query, bounded findings/evidence, persisted risk and counters.
- `src/threatlens/api/app.py` — READ-authorized JSON attachment response and report schema.
- `src/threatlens/ui/index.html`, `src/threatlens/ui/assets/app.js`, `src/threatlens/ui/assets/styles.css` — campaign selector and authenticated JSON download.
- `tests/test_api_app.py`, `tests/test_dashboard_ui.py`, `tests/test_postgres_integration.py` — auth, response, UI, campaign isolation, and raw-evidence exclusion regressions.
- Governing docs: README.md, Architecture.md, MasterInstructions.md, and PROJECT_STATUS.md.

### Validation and security review

- `python -m pytest -q tests/test_api_app.py tests/test_dashboard_ui.py` — 33 passed.
- `ruff check .` — passed; `git diff --check` — passed.
- `python -m pip wheel . --no-deps --wheel-dir work/gate75-wheel` — passed; wheel SHA-256 `fe20dfeae79f3145fa574c7eaa115fb2ab6c7d82411873aa4c8a7c57d6692cf1`.
- User-confirmed on 2026-10-21: `pytest -q -rs tests/test_postgres_integration.py -k campaign_report` completed at 100%; the full `pytest -q -rs` suite completed at 100%; `ruff check .` reported “All checks passed!”; `git diff --check` passed; and the Windows package wheel build succeeded. Five Starlette deprecation warnings were non-failing.
- Security: endpoint requires READ permission, uses a fixed UUID-derived filename, sets no-store/nosniff, selects only evidence linked through the requested campaign's scan execution provenance, never returns raw evidence, and marks bounded output truncation. No new dependencies or writes were introduced.
- No commit or push was made; the user syncs changes through VS Code.

## Gate 76 — Auditable Campaign Report Export — COMPLETE

The Gate 75 campaign report contains security-sensitive findings and evidence metadata, but successful report downloads currently leave no audit event. Add an append-only `CAMPAIGN_REPORT_EXPORTED` event with the authenticated actor, campaign identifier, and bounded report summary metadata. Persist the event transactionally with assembling the report; if audit persistence fails, do not return the report. Preserve READ authorization, campaign scoping, output bounds, raw-evidence exclusion, and response headers.

**Implementation:** `PostgresRepository.campaign_report_export_with_audit()` assembles the bounded report and inserts `CAMPAIGN_REPORT_EXPORTED` in one transaction. The API supplies the authenticated user ID, returns a generic 503 if report/audit persistence fails, and does not return report bytes on that path. API and PostgreSQL regressions cover attribution, success, failure, and missing campaigns. No migration was needed.

**Validation closure:** On 2026-10-21, the user confirmed the report-specific API and PostgreSQL tests and full suite reached 100%; Ruff and `git diff --check` passed; and the Windows wheel built successfully. Five Starlette deprecation warnings were non-failing. Commit `e0dd2d9` (`Audit campaign report exports`) is present on `main` and `origin/main`.

## Gate 77 — Secret Redaction in Evidence Metadata — COMPLETE

The evidence read API redacts secret-like metadata keys and strips URL userinfo, query values, and fragments without modifying persisted evidence or hashes. Safe provenance remains visible. On 2026-10-21, the user confirmed the focused evidence API test and full suite reached 100%, Ruff and `git diff --check` passed, and the Windows wheel built successfully. Five Starlette deprecation warnings were non-failing. Commit `9abd8a8` (`Redact secrets from evidence metadata`) is on `main` and `origin/main`.

## Gate 78 — Retired: Organization Data Model

The user clarified that ThreatLens is a personal project and requested complete removal of organization/membership functionality from the UI, backend, and database. Migration 9 drops the organization tables and ownership columns while preserving campaigns, assets, findings, scans, evidence, and append-only audit history. Historical migration identities 4–8 remain only to support previously migrated databases; migration 9 removes their structures from the active schema. The runtime now reads role directly from the local user record and verifies no organization structures reappear.

## Gate 79 — Bounded Network Service Fingerprinting — COMPLETE

The network provider probes bounded default TCP ports 22, 25, 80, and 443. For supported open ports it performs bounded SSH/SMTP banner collection or fixed HTTP HEAD, normalizes service/product/version, and persists service/evidence through the execution fence. HTTP evidence retains only status and Server headers. On 2026-10-21, the user ran the full PostgreSQL-backed suite against `threatlens_test`; it reached 100% with five non-failing Starlette deprecation warnings.

## Gate 80 — Personal Workspace and Database Cleanup — COMPLETE

The organization panel and organization footer label are removed. Authentication uses the role on the local user account. API/repository tenant filters and organization parameters have been removed. Migration 9 restores global canonical-asset uniqueness, removes legacy organization tables and columns, and preserves persisted assessment/audit rows and audit append-only triggers. A schema verifier fails startup if legacy organization structures remain.

**Validation closure:** On 2026-10-21, migration 9 completed successfully on `threatlens_dev`. The user ran the full PostgreSQL-backed suite against `threatlens_test`; the screenshot showed 100% completion, returned to the prompt, and listed only five non-failing Starlette deprecation warnings. Local Ruff, full runnable pytest, diff check, and Windows wheel build also passed. No commit or push.

## Gate 81 — Evidence-Backed Version-to-CVE Correlation — COMPLETE

The scan persists detected software product separately from its generic service name. Migration 10 adds nullable PostgreSQL `services.product`; migration 11 reconciles stale legacy organization structures while preserving assessment rows; migration 12 stores normalized trusted vulnerability intelligence. The network-free NVD parser only accepts explicit vulnerable exact-version CPE entries. A bounded official NVD client and admin-only import/read APIs enforce rate, response, and role limits; imports are audit-atomic. Network scans query exact product/version matches and emit only `SUSPECTED` findings tied to persisted service evidence through execution-fenced handoff. Findings preserve source and confidence and are not confirmations. On 2026-10-23, the user's latest output confirmed migration, full PostgreSQL-backed tests at 100%, Ruff, `git diff --check`, and wheel build. Five Starlette deprecation warnings were non-failing. Exact test count was not shown.

**Failure and repair history:** The user initially reported PostgreSQL readiness failures because tenant structures remained after migration 9. Migration 11 reruns the idempotent single-user cleanup. A follow-up test regression deleted migration 10 while leaving 11; the test now removes both records and reruns both migrations in order. The user's pgAdmin result confirmed versions 1–9 and 11, so they restored `services.product` and migration 10's exact registry record on `threatlens_test` only. The user later confirmed migrations 10/11 on `threatlens_dev` and most recently migration 12 there.

**Assistant validation of this repair:** `git diff --check` passed. Pytest and Ruff could not be started in this execution environment because the user's venv path resolves to an isolated sandbox `LOCALAPPDATA`; the fallback Python install manager could not reach its runtime index. No PostgreSQL-backed result is claimed for migration 11.

**Follow-up validation attempt:** On 2026-10-23, the user fixed the psycopg/libpq loading issue and confirmed the DSN targets `threatlens_test`. The PostgreSQL-backed tests then failed during connection setup with `password authentication failed for user "postgresql"`; the test role should be `postgres` for this local database. The suite did not reach migration validation. This is a connection configuration failure, not evidence of a migration 11 regression.

**Latest validation:** The user corrected PostgreSQL authentication, repaired the version-10 gap in `threatlens_test`, and applied migrations 10–12 on `threatlens_dev`. On the exact current NVD import/read implementation, the user confirmed migration success, the PostgreSQL-backed suite reached 100%, Ruff reported “All checks passed,” `git diff --check` returned no whitespace errors (only LF/CRLF notices), and the Windows wheel built successfully with SHA-256 `7673243916b3d85dab56b66cb136a89a6dabcad9de1c2fae865b6cb2e41d400c`. Five Starlette deprecation warnings were non-failing; exact pytest counts were not printed.

The user's pgAdmin result on 2026-10-23 confirmed the test ledger initially had versions 1–9 and 11; version 10 (`service_product_fingerprint`) was missing. The user repaired the test DB ledger and column. Later user-provided output confirms migrations 10–12 on `threatlens_dev` and 100% full-suite completion on the current NVD implementation.

**Current cycle — bounded NVD import and persisted read model (user-validated subphase):** The network-free parser accepts only explicit vulnerable exact-version CPE entries and skips ranges, rejected CVEs, negated nodes, and compound AND nodes. A bounded HTTPS client calls the fixed NVD API endpoint, disables redirects, caps responses at 2 MiB, enforces timeouts and process-wide pacing, validates CVE identifiers/response identity, and reads optional `THREATLENS_NVD_API_KEY` only from the API server environment. ADMIN-only `POST /api/v1/cve/ingest` validates up to 10 distinct identifiers before network access and stores imported records atomically with an audit event. READ-authorized `GET /api/v1/cve` is paginated. Migration 12 creates the single-user intelligence table. Added HTTP-client, API, PostgreSQL upsert/audit, and fixture-isolation regression coverage. Updated README.md, Architecture.md, MasterInstructions.md, PROJECT_STATUS.md, and `.env.example`.

**Validation:** Migration 12 and scan-time correlation were confirmed by the user's latest full validation output. The CVE interface is still pending. No commit/push.

**Security review:** Fixed official HTTPS host; no caller-provided URL; redirects disabled; response and request time bounded; process-wide request pacing is six seconds without a key and one second with a key; ID and response identity checked; optional API key remains server-side; errors do not include request credentials or response bodies. Import requires ADMIN, listing requires READ, and data upsert/audit insertion share a transaction. No findings are created by ingestion. Pacing is process-local, so separate API worker processes do not share rate state. Vendor-aware correlation and the CVE UI remain active follow-up work.

## Gate 82 — Vendor-Aware CVE Matching — COMPLETE

The change retains NVD CPE vendor identity beside product and version. Migration 13 adds vendor columns; migration 15 updates the intelligence primary key to include vendor/product without altering an applied migration identity. This prevents separate vendors with the same product name from overwriting each other's CPE records. SQLite persistence round-trips observed vendor metadata. Vendor conflicts reject candidates; an unknown observed vendor lowers confidence. Findings remain `SUSPECTED`.

**Gate 82 validation closure:** The user confirmed the exact-source Windows wheel built successfully on 2026-10-23 with SHA-256 `afb0d9c0d913c942af975540774830b5059678ce77b742aacfe5bc376b8e9f22`. Together with migration recovery, 100% PostgreSQL suite, Ruff, and diff check, Gate 82 is complete. No commit or push.

## Gate 83 — Personal IOC Collection Import and Read API — COMPLETE

Add a bounded, network-free backend to import and review the user's own IOC collections. Start with strict canonical validation for IP addresses, domains, and MD5/SHA-1/SHA-256 hashes; cap each import batch; persist source and confidence; make writes transactional with audit events; and provide a bounded paginated read API. Treat imported values as untrusted data. Do not trigger lookups, callbacks, or scans during import. CSV/file upload and UI integration remain follow-up work after the JSON API is established.

Implementation includes migrations 14–15, strict domain normalization, bounded ADMIN import and READ listing, transactional SQLite/PostgreSQL upserts with audit events, and API/domain/storage regression tests. The user confirmed migrations, the full PostgreSQL-backed suite green after fixing a stale migration-ledger expectation, Ruff, diff check, and Windows wheel build (SHA-256 `0595d1aa0ef407be6d5063814fce8a5077a696ba1461ccc26fe77b87d7639d02`). Six Starlette deprecation warnings were non-failing.

## Gate 84 — Passive Web Security Posture Checks — COMPLETE

Extend the authorized Web Scan with deterministic findings from bounded normal HTTP responses: missing security headers, unsafe cookie attributes where observable, and actionable titles with CWE references. Keep current scope and response caps; never follow redirects, submit forms, fuzz parameters, execute payloads, or store cookie values. Preserve header observations only after redacting cookie secrets. Add tests for duplicate Set-Cookie handling, non-success responses, header presence, and evidence provenance. No database migration should be needed unless the existing finding model cannot represent the needed details.

Implementation adds findings for absent or ineffective CSP, Referrer-Policy, HSTS, XCTO, and clickjacking protections, plus Secure/HttpOnly/SameSite checks on session-like cookies. It preserves multiple Set-Cookie headers and stores only redacted cookie metadata in evidence. Review found that Secure-attribute findings were only emitted for HTTPS and duplicated the SameSite=None case; the implementation now reports a missing Secure attribute for any observed session cookie exactly once. The user first ran pytest with the database URL unset, which skipped 103 PostgreSQL cases; after correctly setting and verifying `threatlens_test`, the user confirmed the full suite reached 100% without a skip summary, Ruff passed, and `git diff --check` succeeded (only LF/CRLF notices). The exact-source Windows wheel built successfully with SHA-256 `815b6a24043acbd3586dd613f1b901aea83893a9ee2149c464ad97f5b54be8e4`. Six Starlette deprecation warnings were non-failing.

## Gate 85 — Network Scan DNS Resolution Boundary — COMPLETE

The network provider accepts FQDN targets but passes the hostname directly to TCP connect and the service interrogation probe. It does not resolve and validate the destination before connecting, so a scoped name that resolves to loopback, link-local, reserved, or private infrastructure can cause the scanner to access an unintended network. Resolve names once, validate all answers before any socket access, pin connection and interrogation to a validated address, and preserve the original authorized hostname as the asset identity. Keep explicitly scoped literal IP targets (including private IPs) usable for authorized internal assessments. Fail closed for empty, malformed, or disallowed hostname resolutions; add deterministic tests proving no probe occurs on rejected DNS answers. No schema migration or GUI change is expected.

The provider resolves each scoped hostname once per execution, rejects non-global/mixed answers by default (with a 16-address bound), records the validated address in evidence, and pins both TCP connect and HTTP/banner interrogation while retaining the original HTTP Host value. Explicit literal private IPs bypass DNS and remain scannable. Regression tests cover pinning, rejected loopback/mixed answers, internal IP targets, and HTTP Host preservation.

**Validation closure:** On 2026-10-23, the user confirmed the exact source passed the full PostgreSQL-backed suite at 100%, Ruff, `git diff --check`, and Windows wheel build (SHA-256 `983bfd20ec1c0fe2cbfa4795b1cdc40aa5859d72eef03a018dee77474ed31a9e`). Six Starlette deprecation warnings were non-failing. A stray `l` typed after the wheel-success check caused a separate PowerShell command-not-found message and did not invalidate the successful build.

## Gate 86 — Web/API Scan DNS Pinning — COMPLETE

Web and API providers validated DNS answers but then passed the original hostname to urllib, which resolved DNS again at socket-connect time. DNS rebinding could therefore redirect the request to an unvalidated internal destination. The HTTP probe now connects to the validated IP directly while retaining the original hostname for the HTTP Host header and, for HTTPS, TLS SNI and normal certificate hostname verification. Empty DNS answers fail closed; oversized answers are bounded; multicast and unspecified destinations remain prohibited even when explicitly scoped private addresses are enabled. Redirects remain disabled and response limits remain unchanged.

**Validation closure:** On 2026-10-23, the user confirmed the full PostgreSQL-backed suite reached 100%, Ruff passed, `git diff --check` passed with only LF/CRLF notices, and the Windows wheel built successfully (SHA-256 `58e7658678bab6ec3402cc1561bb26c1bba6898884a1040c4d079c630099369b`). Six Starlette deprecation warnings were non-failing.

## Gate 87 — TLS Scan DNS Pinning — COMPLETE

TLS Scan previously connected to scoped hostnames directly, allowing a second uncontrolled DNS lookup and permitting a DNS name to resolve to internal addresses. The provider now resolves and validates hostname answers once per execution, rejects empty/oversized/mixed non-public answer sets by default, pins the TLS socket to the validated destination, and preserves the original hostname for SNI and certificate verification. Explicitly scoped literal private IP addresses remain usable; multicast and unspecified addresses are always denied.

**Validation closure:** On 2026-10-23, the user confirmed the full PostgreSQL-backed suite reached 100%, Ruff passed, `git diff --check` passed, and the Windows wheel built successfully (SHA-256 `3e2a4638b7528d0b8e25d22194d6518658e50e764abdc791bb35c8acb23cde87`). Six Starlette deprecation warnings were non-failing.

## Gate 88 — Standalone Service Interrogation DNS Pinning — COMPLETE

The built-in `ActiveServiceInterrogationProvider` can be instantiated independently from Network Scan and currently passes scoped FQDNs to a socket probe that resolves them at connect time, without rejecting private DNS answers. Add the same fail-closed hostname resolution and validated-address pinning used by the network path, preserving the original host as the banner's Host identity and allowing explicitly scoped literal private IPs. Keep protocol, port, timeout, byte, cancellation, and evidence limits unchanged.

**Validation closure:** On 2026-10-23, the user confirmed the full PostgreSQL-backed suite reached 100%, Ruff passed, `git diff --check` passed, and the Windows wheel built successfully (SHA-256 `42b21abcf780d08056024a084b476566e2567d6c603248b883fa3eecfe0db44c`). Six Starlette deprecation warnings were non-failing.

## Gate 89 — Network Scan TLS Observation Integration — COMPLETE

Network Scan previously stopped at TCP-open evidence on ports 443/8443, leaving the existing TLS probe and deterministic TLS policy findings disconnected from the default target-only scan workflow. The default API Network Scan now injects the bounded TLS probe; only a TCP-open 443/8443 target reaches TLS inspection, pinned to the same validated destination address and original hostname. TLS observations are sealed and persisted through ProviderHandoff under TLS provider provenance, then policy findings reference that persisted evidence. Focused tests cover pinned TLS evidence/finding persistence and the closed-port short circuit.

Validation closure: on 2026-10-23, focused Web/API tests and the full pytest suite reached 100% with full-run exit code 0; Ruff, `git diff --check`, and the Windows wheel build passed. Wheel SHA-256: `750799068f195d4908e613fb26790eb19669eea52f4082576f6bac2dfe443acd`. Six Starlette deprecation warnings were non-failing; explicit passed/skipped totals were not present in the captured summary.

## Gate 90 - HTTP Response Evidence Minimization - COMPLETE

Web/API evidence previously persisted raw response excerpts, arbitrary response headers, redirect destinations, and request URLs with potential userinfo, query credentials, or fragments. The implementation stores a SHA-256 digest and byte count instead of body text; allowlists response headers and redacts cookie values; records only whether a redirect was observed; and removes URL userinfo, query strings, and fragments from persisted evidence and URL metadata. The API provider still evaluates the bounded body in memory for its existing JSON check. Network requests, scope validation, and redirect suppression are unchanged.

**Gate 82 validation failure and repair:** The user's first full run reached 100% but reported 9 PostgreSQL fixture setup errors, one PostgreSQL schema-migration failure, and one TLS source assertion failure. The migration regression test had removed versions 11 and 12 but left version 13 recorded, creating a migration-history gap; the test database retained that gap and temporary legacy tenant structures. The test now removes versions 11–13 together so all are reapplied in order. Recovery was restricted to `threatlens_test`; registry entries 11–13 were removed, then test initialization reapplied them and reran the single-user cleanup. A `ProviderHandoff` regression also appended source labels for non-CVE findings; source composition is now limited to CVE findings so TLS semantics stay unchanged. The user confirmed the corrected full suite at 100%, Ruff, diff check, and later the exact-source Windows wheel build with SHA-256 `afb0d9c0d913c942af975540774830b5059678ce77b742aacfe5bc376b8e9f22`. Gate 82 is complete.
