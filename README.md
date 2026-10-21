# Advanced VAPT System

## Project Status

The repository is governed by:

- README.md
- Architecture.md
- MasterInstructions.md

Implementation follows an evidence-first, safety-controlled VAPT orchestration model.

## Core Objective

Build a production-grade, authorized VAPT orchestration platform that integrates asset discovery, attack-surface management, network/web/API/infrastructure assessment, vulnerability intelligence, normalized evidence, finding correlation, risk analysis, attack-path analysis, validation, remediation tracking, campaign orchestration, and professional reporting.

## Engineering Principle

DISCOVER → UNDERSTAND → VALIDATE → CORRELATE → PRIORITIZE → REMEDIATE → VERIFY

Evidence over assumption. Correlation over duplication. Risk over raw vulnerability count. Architecture over quick hacks. Security over convenience.

## Current State

### Completed

- Foundational domain contracts for campaign, scope, asset, service, scan, evidence, and finding.
- Explicit campaign authorization and execution safety policy.
- PostgreSQL persistence boundary with database constraints, foreign-key integrity, transactional lifecycle semantics, and `psycopg` as the runtime driver.
- SQLite is not a production/deployment backend; any remaining SQLite adapter code is legacy test compatibility only and must not become a second production persistence path.
- Persisted scan execution IDs and fail-closed lifecycle transitions.
- Campaign/scan orchestration boundary with provider isolation and cancellation semantics.
- Provider registry with explicit metadata and capability declarations.
- Provider execution runtime with structured execution events, execution metrics, failure capture, and cooperative timeout/cancellation signaling.
- Evidence-first provider handoff with immutable evidence sealing, SHA-256 content integrity, execution/provider provenance, and finding/evidence validation.
- Controlled discovery provider that normalizes only authorized campaign targets, honors exclusions/cancellation, persists normalized assets, and records discovery evidence without claiming vulnerabilities or performing network probing.
- Controlled TCP network discovery adapter with explicit host allowlisting through campaign scope, exclusion enforcement, bounded target count, bounded ports, per-connect timeout, cooperative cancellation, service normalization, and evidence provenance.
- Service identification and protocol metadata normalizer for bounded observations, with explicit protocol classification, product/version extraction, confidence, and banner-size limits. Identification remains an observation layer and does not create vulnerability claims.
- Controlled active service interrogation provider using only explicit, bounded protocol probes for authorized in-scope hosts, with target/port/response limits, cancellation, timeout, and evidence provenance.
- Controlled TLS assessment provider with bounded TLS handshake inspection, certificate metadata capture, hostname verification state, cipher/protocol observation, timeout/target limits, exclusion enforcement, cancellation, and evidence provenance.
- Controlled web assessment provider with bounded HTTP(S) HEAD/GET observation, redirect suppression, destination safety validation, response limits, evidence-first handoff, and conservative header policy findings.
- Controlled API assessment foundation with explicit API URL targets, bounded read-only HEAD/GET requests, redirect suppression, destination safety validation, JSON response evidence, and conservative malformed-JSON policy evaluation.
- Deterministic TLS security-policy evaluation for deprecated TLS versions, certificate validation failures, hostname mismatch, certificate expiration, and weak/deprecated ciphers.
- End-to-end TLS finding handoff through persisted evidence, asset resolution, normalized finding validation, and the existing ProviderHandoff boundary.
- Deterministic cross-provider finding correlation using asset identity plus vulnerability identity (or normalized title/CWE fallback), with stable logical finding IDs and preservation of all unique evidence and contributing provider sources.
- Automated persistence, orchestration, provider-runtime, evidence-handoff, discovery, network-discovery, identification, interrogation, TLS assessment, TLS finding integration, API assessment, vulnerability-intelligence normalization/matching, finding-correlation, risk-engine, attack-path, and evidence-validation tests.
- Trusted vulnerability-intelligence normalization with strict CVE/CWE validation, bounded metadata, provenance, and optional evidence references.
- Deterministic vulnerability matching requiring explicit product and exact version agreement; no CVE inference or unsupported vulnerability claims.
- Evidence-backed vulnerability finding enrichment routed through ProviderHandoff, preserving asset identity, intelligence provenance, CVE/CWE/CVSS/severity metadata, and all required evidence references.
- Context-aware vulnerability correlation using explicit service, endpoint, parameter, and location identity without merging contextual findings into context-free findings.

### Current Architecture Gate

Gate 49 — Durable Cross-Instance Scan Command Idempotency: COMPLETE. Gate 50 — Cross-Instance Scan Command Retry/Recovery Serialization: COMPLETE. Gate 51 — Fail-Closed Scan Heartbeat Lease Integrity: COMPLETE.

Gate 52 — Execution-Lease-Fenced Evidence and Finding Persistence: implementation and PostgreSQL-backed tests validated on 2026-10-14; see `PROJECT_STATUS.md`.

Gate 53 — Durable Finding Remediation Idempotency: implementation and PostgreSQL-backed tests validated on 2026-10-14; exact retries replay without duplicate audit events and conflicting key reuse returns HTTP 409.

Gate 54 — Versioned PostgreSQL Schema Migrations: COMPLETE. On 2026-10-14, the user confirmed the migration tests, focused remediation tests, full PostgreSQL-backed test suite, Ruff, diff checks, and wheel build all passed against main commit f0f4d543947f864ff05d6e7173839b105562cd2c. Five Starlette deprecation warnings were non-failing.

Gate 55 — Database-Enforced Append-Only Security Audit Trail: COMPLETE. On 2026-10-14, the user confirmed focused migration tests (4 passed), focused remediation tests (14 passed), the full PostgreSQL-backed test suite, Ruff, diff checks, and package wheel build all passed on main commit 8dcb6974132713bf426b30bfc202260c9a5ff699. Five Starlette deprecation warnings were non-failing.

Gate 56 — PostgreSQL Audit Trail Truncation Protection: COMPLETE. On 2026-10-14, the user confirmed 4 focused migration tests, 14 focused remediation tests, the full PostgreSQL-backed suite at 100% with no skip summary, Ruff, diff checks, and wheel build passed on `4e96495a5ee85e23b35033f364f379120898d159`.

Gate 57 — Fail-Closed Audit Protection Drift Detection: COMPLETE. Startup validates required PostgreSQL audit triggers using catalog trigger-type bits, enabled state, event/row-or-statement semantics, trigger-function identity, and exact normalized fail-closed function behavior. PostgreSQL regressions cover disabled, missing, and weakened-function drift plus connection transaction-state cleanup. On 2026-10-14, the user confirmed 8 focused schema migration tests, the full PostgreSQL-backed suite without a skip summary, Ruff, diff checks, and wheel build passed on `db3b98165bb10351cb3fc2b10de964c44a5dcd90`. Five Starlette deprecation warnings were non-blocking.

Gate 58 — PostgreSQL Runtime/Migration Privilege Separation: COMPLETE. On 2026-10-14, the user confirmed 37 focused PostgreSQL migration/runtime-privilege/API tests passed, the full pytest suite reached 100% without a skip summary, Ruff and diff checks passed, and the package wheel built successfully on main commit `c39a7cd9d757e2a63cc27365e6e2b8e8a5e529b3`. The wheel SHA-256 was `6867d9542088c520678beee241b1fd26ebc0fb73885ea6f4c16bbc5f4bf1fb25`. Five Starlette deprecation warnings were non-failing. API startup uses the runtime DSN only for read-only schema/readiness verification; migrations run explicitly with `THREATLENS_MIGRATION_DATABASE_URL` using `python -m threatlens.storage.migrate`.

Gate 59 — Fail-Closed Runtime Database Privilege Verification: COMPLETE. On 2026-10-14, the user confirmed 43 focused PostgreSQL migration/runtime-privilege/API tests passed, the full PostgreSQL-backed suite reached 100% without a reported failure or skip summary, Ruff and diff checks passed, and the package wheel built successfully on main commit 78f7856677d029c2f01d0000831b080e16c8f45c. Wheel SHA-256: f5315fe6366d53d9607e11aa1f4624978266c3e29a75376377bd17d03d63bb71. Five Starlette deprecation warnings were non-failing. The user confirmed generated build artifacts were removed and the working tree was clean.

Gate 60 — Fail-Closed Runtime Ownership Boundary for Application Schema Objects: COMPLETE. On 2026-10-14, the user confirmed the focused PostgreSQL privilege/ownership tests, full PostgreSQL-backed test suite, Ruff, diff check, and wheel build were clean and successful on main revision `080cc28ee38a207f3a5da83f36497510495a4a1a`. No failures were reported.

Gate 61 — Fail-Closed Runtime Relation Privilege Verification: COMPLETE. On 2026-10-14, the user confirmed all focused PostgreSQL migration/runtime privilege/API tests, the full PostgreSQL-backed suite, Ruff, diff check, and wheel build completed cleanly on main revision `0c6f22281f3242187ec2c1b3165b50557d9665d1`; no failures were reported.

Gate 62 — Fail-Closed Runtime Sequence Privilege Verification: COMPLETE. On 2026-10-14, the user confirmed clean and successful validation. Startup rejects effective SELECT, USAGE, or UPDATE privileges on application-schema sequences for either runtime identity, including inherited grants.

Architecture Gate 49: Durable Cross-Instance Scan Command Idempotency — COMPLETE. The authenticated scan-queue API requires a bounded Idempotency-Key; PostgreSQL atomically persists the request fingerprint, queued scan, and SCAN_QUEUED audit event under a transaction-scoped advisory lock. Exact retries return the original execution, conflicting key reuse is rejected, and PostgreSQL integration coverage verifies rollback and two-connection concurrency. The user confirmed focused API/PostgreSQL tests, the full pytest suite, Ruff, diff checks, and package wheel build passed; the changes are merged and verified on main. Gate 50 — Cross-Instance Scan Command Retry/Recovery Serialization — COMPLETE. The user confirmed validation success, including the Ruff correction. Lifecycle control endpoints require durable idempotency keys; PostgreSQL serializes actor/key retries and atomically persists command results with lifecycle audit events. Gate 51 — Fail-Closed Scan Heartbeat Lease Integrity — COMPLETE. Provider execution now treats heartbeat renewal failure or lease loss as a hard execution failure, requests cooperative cancellation, maps lease loss to FAILED rather than user cancellation, and stops the heartbeat worker after completion. The user confirmed clean/successful validation, including the package wheel build. Gate 52 — Execution-Lease-Fenced Evidence and Finding Persistence — COMPLETE after PostgreSQL-backed tests executed successfully on 2026-10-14. PostgreSQL provider handoff now locks and verifies the originating scan remains RUNNING in the same transaction as evidence/finding writes; durable finding correlation applies the same execution fence before merging or inserting a logical finding. Production repositories declare that execution fencing is mandatory, and ProviderHandoff/DurableFindingCorrelator fail closed instead of falling back to legacy writes when the fence is unavailable. PostgreSQL also rejects execution-bound evidence sent through the unfenced save_evidence method. Regression tests cover missing-fence fallbacks and unfenced execution-bound evidence in addition to late evidence/finding rejection, correlated writes, active execution output, and terminal-transition races. Gate 52's PostgreSQL-backed execution-fence regressions were confirmed executed on 2026-10-14; see the gate status section below. See PROJECT_STATUS.md for the per-cycle report and feedback. Gate 48 Authenticated Security Audit Read Model API is complete. Gate 43 Authenticated Attack-Path Relationship Control API is complete after local pytest and Ruff validation. Gate 38 Authenticated Campaign & Scope Control API is complete after explicit local validation. Gate 20 PostgreSQL Transactional Concurrency and Failure-Recovery Hardening is complete after local validation. PostgreSQL is now the sole active development/test persistence path; the legacy SQLite adapter is not used by the application or active test suite. Gate 18 Reliability and Performance remains complete with durable heartbeat leases, explicit authenticated stale recovery, bounded provider concurrency, compare-and-set lifecycle transitions, atomic persistence/audit mutations, and explicit handling of non-cooperative provider timeouts.

### Architecture Gate 35 — Authenticated Evidence Read Model API — COMPLETE

Gate 35 adds the authenticated `GET /api/v1/evidence` read model for immutable evidence metadata. The endpoint requires READ permission, uses bounded pagination, and exposes evidence identity, kind, source, capture time, SHA-256 integrity identity, and bounded metadata without exposing raw evidence content.

The endpoint is strictly read-only. Evidence integrity remains anchored by the sealed SHA-256 digest, while evidence validation transitions remain governed by the existing append-only persistence contract. PostgreSQL remains authoritative and uses fixed, bounded SQL with deterministic ordering.

Gate 35 is complete after explicit local validation.

### Architecture Gate 36 — Authenticated Evidence Validation Lifecycle API

Gate 36 adds authenticated lifecycle control for evidence validation. Validation creation requires VALIDATE permission and binds the validator/audit actor to the authenticated principal. Existing lifecycle transitions remain fail-closed, final decisions require supporting evidence, evidence SHA-256 integrity is rechecked, and PostgreSQL commits the immutable validation record together with its security audit event transactionally.

The API does not expose raw evidence mutation, arbitrary SQL, provider execution, or client-selected validator identity.

### Gate 19 PostgreSQL Enforcement — COMPLETE

The active persistence test suite now runs through PostgreSQL only. The shared integration fixture requires `THREATLENS_TEST_DATABASE_URL` or the canonical `THREATLENS_DATABASE_URL`, never falls back to SQLite, initializes the schema, isolates tests with `TRUNCATE ... CASCADE`, and covers domain persistence, foreign-key integrity, authentication, durable correlation, evidence validation, scan lifecycle CAS, concurrency-sensitive orchestration, and PostgreSQL trigger-based failure-atomicity scenarios. The repository contains no active test-suite imports of `SQLiteRepository`. The SQLite adapter is retained only as legacy compatibility code and receives no new production behavior.

### PostgreSQL Deployment Readiness and Database Roles

PostgreSQL is the permanent and canonical deployment persistence target. The application does not auto-start or auto-create a database server. Keep runtime and migration credentials separate:

- `THREATLENS_DATABASE_URL`: runtime identity used by the API. It must not own schema objects or have schema `CREATE` privileges.
- `THREATLENS_MIGRATION_DATABASE_URL`: deployment/migration identity used only by the explicit migration command.

Provision both roles through a trusted DBA/deployment process. For a new, dedicated database, the following is a reference pattern to adapt to your database/schema names and credential manager (run as a database administrator; do not put real passwords in source control):

```sql
CREATE ROLE threatlens_migrator LOGIN PASSWORD 'set-via-secret-manager';
CREATE ROLE threatlens_runtime LOGIN PASSWORD 'set-via-secret-manager';
GRANT CONNECT ON DATABASE threatlens TO threatlens_migrator, threatlens_runtime;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO threatlens_migrator;
GRANT USAGE ON SCHEMA public TO threatlens_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE threatlens_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO threatlens_runtime;
```

Then apply migrations with the migration identity:

```bash
python -m threatlens.storage.migrate
```

After migration, grant the runtime identity data access to existing application tables, while explicitly restricting the audit trail:

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO threatlens_runtime;
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON audit_events FROM threatlens_runtime;
GRANT SELECT, INSERT ON audit_events TO threatlens_runtime;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON threatlens_schema_migrations FROM threatlens_runtime;
GRANT SELECT ON threatlens_schema_migrations TO threatlens_runtime;
REVOKE CREATE ON SCHEMA public FROM threatlens_runtime;
```

Use the same migration owner for subsequent schema changes so its default privileges apply. Existing installations may need a DBA-led ownership transfer before the migration identity can safely manage pre-existing objects. The runtime role must not be a member of the migration role, table owner, database owner, or superuser. Test the effective grants in the target environment; role membership and inherited grants can otherwise defeat a direct REVOKE.

For local development, configure both DSNs in an untracked `.env`. Run the migration command before starting the API. API startup verifies the migration registry and audit protections but does not apply DDL. The PostgreSQL integration suite continues to use `THREATLENS_TEST_DATABASE_URL` and requires a test database role with permission to initialize and reset its isolated schema.

### Architecture Gate 26 — Vulnerability Correlation Context Expansion — COMPLETE

Gate 26 expands deterministic finding identity beyond asset and vulnerability identity. Findings may now carry explicit service, endpoint, parameter, and location context. Correlation includes every supplied context dimension, normalizes textual context deterministically, and refuses to merge context-bearing findings with context-free findings. PostgreSQL and legacy SQLite persistence retain the context fields so durable correlation uses the same identity as in-memory correlation.

**Validation status:** Gate 26 focused regression tests are implemented but require local `pytest -q` and `ruff check .` execution before completion.

### Architecture Gate 27 — Risk Context Provenance — COMPLETE

Gate 27 requires explicit provenance for supplied environmental risk context. Risk assessments now retain the source of environmental inputs, and supplied context without a declared source is rejected rather than treated as anonymous telemetry. This keeps risk scoring explainable and prepares the risk layer for auditable GUI drill-downs.

Gate 27 is complete after explicit local validation.

### Validation Limitation

Repository changes are verified through GitHub. Local pytest, lint, build, PostgreSQL connectivity, and runtime execution must be performed in the development environment; no result is claimed here unless actually executed.

## Architecture Gate 17 Status

Authentication is now a first-class backend boundary. Users use PBKDF2-HMAC-SHA256 password hashes, successful logins receive short-lived opaque sessions whose hashes are persisted, revoked sessions fail closed, role permissions are explicit, authentication/authorization decisions are audited, and assessment orchestration requires an authenticated principal with ASSESS permission. Viewer principals cannot execute assessments. PostgreSQL persists users, sessions, and audit events without storing raw session tokens. SQLite is not part of the production authentication/persistence deployment path.

## Architecture Gate 18 Status

Provider execution now has a bounded cancellation-grace policy after timeout. A timeout always sets the cancellation event and never reports success. If a provider ignores cancellation beyond the grace budget, the runtime explicitly reports `worker_still_running` instead of pretending the worker was terminated. Runtime event collection is protected for concurrent provider/observer activity. This is cooperative cancellation hardening; Python threads are not forcibly killed.

## Gate 18 Reliability Hardening Update

Scan lifecycle finalization now uses atomic repository compare-and-set transitions. External cancellation can atomically win over provider completion/failure, and late completion attempts observe the already-terminal state instead of overwriting it. SQLite and PostgreSQL expose the same race-safe lifecycle primitives. Cancellation of an already-terminal scan is an explicit no-op and is audited as such.

## Gate 18 Reliability Hardening Update — Concurrency and Persistence Boundaries

Provider execution now enforces ExecutionPolicy.max_concurrency through a shared bounded semaphore at the orchestrator runtime boundary. The limit counts actual provider worker lifetime: a timed-out non-cooperative worker retains its execution slot until the worker exits, preventing hidden concurrency overflow. Waiting executions remain cancellation-aware before acquiring a slot.

SQLite scan lifecycle operations now execute their read/validate/write state transitions inside one repository transaction and use a repository lock for concurrent lifecycle access. SQLite permits cross-thread repository cancellation safely while preserving serialized connection use. PostgreSQL now exposes the same transactional update_scan_state() contract, locks lifecycle rows during read/validate/write transitions, and serializes scan/audit transaction access. Pre-start cancellation uses the atomic cancellation primitive.

## Gate 18 Reliability Hardening Update — Persistence Failure Atomicity and Recovery

Scan creation, lifecycle finalization, and cancellation now use repository-level atomic transactions that couple the state mutation with its audit event. If the audit write or lifecycle write fails, the transaction rolls back and the persisted scan state is not partially advanced.

Provider execution failures are handled separately from persistence failures. A successful provider is never reclassified as a provider failure merely because lifecycle finalization persistence failed. The persistence exception is allowed to surface fail-closed, leaving the last durable lifecycle state authoritative for deterministic recovery.

Recovery is explicit: after a persistence failure, operators can inspect the authoritative persisted state and retry the valid lifecycle transition once the persistence fault is removed. SQLite and PostgreSQL implement the same atomic repository contract.

## Next Architecture Direction

After local validation of this hardening, continue Gate 18 reliability/performance review with any remaining transaction-boundary races before advancing to the next architecture priority.


## Gate 18 Reliability Hardening Update — Execution Heartbeat and Stale Recovery

Running scans now maintain a durable execution heartbeat. The runtime refreshes the heartbeat while provider work remains active, and the policy defines both a heartbeat interval and a stale-after threshold. A running execution is never recovered solely because it is old: stale recovery requires an expired heartbeat lease. Recovery is an explicit authenticated orchestration action that atomically transitions the stale execution to FAILED and records the recovery audit event. This prevents blind provider reruns after process interruption while providing a deterministic operator recovery path.


### Architecture Gate 20 — COMPLETE

Gate 20 hardens PostgreSQL for cross-instance lifecycle and correlation races. Finding correlation persistence now uses a transaction-scoped PostgreSQL advisory lock plus row locking so independent ThreatLens instances converge on one deterministic logical finding. Evidence-validation transitions lock the current validation record before state changes. Cross-instance orchestration tests cover stale-recovery winner selection and cancellation versus provider finalization races. PostgreSQL transaction boundaries remain authoritative for lifecycle/audit mutations and failure recovery.

### Architecture Gate 21 — Controlled Web Assessment Foundation — COMPLETE

Gate 21 establishes the first bounded HTTP assessment boundary for explicitly scoped HTTP(S) URLs. The built-in web provider supports only HEAD by default and an explicitly configured bounded GET; it disables redirect following, rejects URL userinfo and fragments, enforces target limits/timeouts/response-size limits, and blocks destinations resolving to private, loopback, link-local, or reserved addresses unless private addressing is explicitly enabled for an authorized assessment environment.

HTTP observations are persisted as sealed evidence before policy findings are emitted. The deterministic web policy currently evaluates only conservative response-header controls: missing HSTS on successful HTTPS responses and missing X-Content-Type-Options. Findings retain the exact evidence reference and are sent through ProviderHandoff rather than written directly to persistence. Redirect targets are evidence only and are never followed or treated as newly authorized scope.

API-specific authenticated workflows, schema-driven API discovery, parameter fuzzing, state-changing requests, SSRF exploitation, authentication bypass testing, and intrusive web testing remain outside this gate and require a separate explicit API assessment gate.


### Architecture Gate 22 — Controlled API Assessment Foundation — COMPLETE

Gate 22 is complete after clean local pytest and Ruff validation. The API assessment foundation remains bounded to explicit HTTP(S) API targets, read-only HEAD/GET behavior, destination safety checks, redirect suppression, bounded captures, evidence-first persistence, and conservative malformed-JSON policy evaluation.

### Architecture Gate 23 — Vulnerability Intelligence Foundation — COMPLETE

Gate 23 establishes a provider-independent vulnerability-intelligence contract for trusted upstream metadata. Intelligence records normalize vulnerability identifiers, severity, CVE/CWE identifiers, affected product/version metadata, CVSS, confidence, references, source provenance, and optional evidence references. Invalid identifiers and out-of-range confidence/CVSS values are rejected. The boundary is network-free and never fetches feeds or invents vulnerability data.

### Architecture Gate 24 — Deterministic Vulnerability Matching — COMPLETE

Gate 24 adds deterministic matching between normalized service observations and trusted vulnerability intelligence. A match requires the same authorized asset, an explicit product/service-name agreement, and an exact observed-version match against the intelligence record's affected-version set. Missing product/version metadata, different assets, and non-exact versions produce no match. Matching returns a rationale, bounded confidence, source provenance, and the service identity without creating a finding or asserting exploitability; later finding enrichment must still cross ProviderHandoff and preserve evidence requirements.



**Validation status:** Gate 22 was locally validated clean by the development environment. Gates 23–24 include focused regression tests but require local execution of `pytest -q` and `ruff check .` before they may be declared complete.


### Architecture Gate 25 — Evidence-Backed Vulnerability Finding Enrichment — COMPLETE

Gate 25 connects trusted vulnerability intelligence to an existing normalized finding without creating unsupported findings. Enrichment requires a deterministic vulnerability match and the intelligence record's evidence references must be present in the same ProviderHandoff input. The resulting finding preserves the original evidence, adds trusted intelligence evidence, applies normalized vulnerability identity/CVE/CWE/CVSS/severity metadata, and remains subject to the normal ProviderHandoff validation and durable correlation boundary.

The enrichment layer is network-free and cannot fetch intelligence, infer affected versions, or bypass evidence requirements. Intelligence-backed metadata is therefore an evidence-supported augmentation of an existing finding rather than an assertion that a service is exploitable.

Gate 25 is complete after explicit local validation.


### Architecture Gate 28 — Application API Boundary Foundation — COMPLETE

Gate 28 establishes the authenticated HTTP control-plane boundary required by the future GUI. The application exposes a public health endpoint plus versioned authentication endpoints for login, logout, and the authenticated current-principal view. Session tokens remain opaque to the client-side domain layer, are validated through AuthenticationService, and are never persisted in raw form. Authorization remains enforced through the existing permission model.

The API uses dependency injection for repository and authentication services, so HTTP transport does not bypass domain or persistence boundaries. The initial surface is intentionally read/control oriented; assessment execution, campaign mutation, findings, evidence, risk, attack-path, and reporting endpoints will be added only after their corresponding application contracts are defined.

Gate 28 is complete after explicit local validation.


### Architecture Gate 29 — Dashboard Read Model API — IMPLEMENTED

Gate 29 adds the first authenticated GUI-facing read model: a bounded dashboard summary containing campaign, asset, service, finding, severity, and scan-state aggregates. The API exposes this only through the existing READ permission boundary; the frontend receives an application-level view model rather than arbitrary SQL or database rows.

The summary is PostgreSQL-backed, read-only, deterministic, and intentionally aggregate-only. Detailed findings, evidence, risk, and attack-path endpoints will remain separate contracts so authorization and data exposure can be controlled independently.

**Validation status:** Gate 29 focused API regression tests are implemented and require local pytest -q and ruff check . execution before completion.


### Architecture Gate 30 — Findings Read Model API — IMPLEMENTED

Gate 30 establishes the authenticated GUI-facing findings read model at `GET /api/v1/findings`. The endpoint exposes bounded, paginated finding metadata with asset identity and explicit service/endpoint/parameter/location context, while excluding raw evidence content and arbitrary database access. Results require READ permission and use deterministic ordering by detection time and finding ID.

The PostgreSQL repository uses fixed SQL with an enforced maximum page size of 100. The API contract is read-only and preserves the evidence boundary: detailed evidence retrieval remains a separate least-privilege contract.

**Validation status:** Gate 30 focused API regression tests are implemented. Local `pytest -q` and `ruff check .` are required before the gate can be declared complete.


### Architecture Gate 33 — Campaign & Scope Read Model API — COMPLETE

Gate 33 establishes the authenticated GUI-facing campaign and authorization-scope read model at `GET /api/v1/campaigns`. The endpoint requires READ permission and returns bounded campaign identity, authorization state, lifecycle state, creation time, and the explicit include/exclude scope entries.

PostgreSQL uses fixed SQL with a maximum page size of 100 and deterministic ordering. Scope is read directly from the persisted authorization boundary; the API does not infer targets, expand ranges, or normalize scope into newly authorized destinations. The endpoint is read-only and excludes credentials, evidence content, audit records, arbitrary SQL, and campaign mutation.

Gate 33 is complete after explicit local validation.

### Architecture Gate 34 — Authenticated Scan Lifecycle Control API — COMPLETE

Gate 34 exposes the existing `ScanOrchestrator` lifecycle controls through the authenticated application boundary without duplicating lifecycle logic in FastAPI. `POST /api/v1/scans/{execution_id}/cancel` and `POST /api/v1/scans/{execution_id}/recover-stale` require `ASSESS` permission and route the authenticated principal into the existing orchestrator, which remains responsible for campaign/scan authorization, transactional compare-and-set lifecycle semantics, heartbeat lease recovery, and audit events.

The control responses report the authoritative persisted lifecycle state and whether the requested recovery changed state. Unknown execution IDs return not-found, malformed identifiers fail validation, terminal cancellation is an explicit idempotent no-op, and no provider is invoked by these control endpoints. The API therefore cannot bypass the existing orchestration or persistence safety boundaries.

Gate 34 is complete after explicit local validation.

### Architecture Gate 32 — Scan Read Model API — COMPLETE

Gate 32 establishes the authenticated GUI-facing scan execution read model at `GET /api/v1/scans`. The endpoint requires READ permission and returns bounded execution metadata including campaign identity, provider, lifecycle state, queue/start/finish timestamps, heartbeat state, and a bounded error summary when present.

PostgreSQL uses fixed SQL with a maximum page size of 100 and deterministic ordering. The endpoint is read-only and excludes raw evidence, credentials, audit records, arbitrary SQL, and provider-internal execution details. It exposes operational state only; it does not mutate scan lifecycle state or bypass orchestration authorization.

Gate 32 is complete after explicit local validation.

### Architecture Gate 31 — Asset & Service Read Model API — COMPLETE

Gate 31 establishes the authenticated GUI-facing attack-surface inventory contract at `GET /api/v1/assets`. The endpoint returns bounded asset identity and explicitly observed service metadata, including protocol, port, service name, and version. Pagination is capped at 100 records per request.

The read model uses fixed PostgreSQL queries and deterministic ordering. It does not expose arbitrary SQL, raw evidence, credentials, audit records, or unrestricted database rows. Service data is presented as observation context for the asset inventory; it does not itself assert vulnerability or exploitability.

**Validation status:** Gate 31 focused API regression tests are implemented. Local `pytest -q` and `ruff check .` are required before the gate can be declared complete.


### Architecture Gate 37 — Authenticated Scan Queue Control API — COMPLETE

Gate 37 exposes the existing `ScanOrchestrator.queue()` boundary through an authenticated HTTP control-plane endpoint: `POST /api/v1/campaigns/{campaign_id}/scans`. The endpoint requires ASSESS permission, resolves the persisted campaign and an explicitly registered provider, and delegates queueing to the orchestrator so campaign authorization, execution policy validation, scan creation, and audit persistence remain in one existing application boundary.

The API only creates a QUEUED scan; it does not execute a provider, expand campaign scope, accept arbitrary provider implementations, or permit client-controlled audit identity. Provider selection is constrained to the injected `ProviderRegistry`, and the authenticated principal is passed unchanged to the orchestrator.

Gate 37 is complete after explicit local validation.


### Architecture Gate 38 — Authenticated Campaign & Scope Control API

Gate 38 establishes the authenticated campaign authorization control boundary. `POST /api/v1/campaigns` requires ADMIN permission and requires an explicit authorization acknowledgement before a campaign can be persisted. The request is normalized through the existing immutable `Campaign` and `Scope` domain contracts, so blank names, empty include scope, and blank scope entries fail closed.

Campaign persistence and the `CAMPAIGN_CREATED` security audit event are committed atomically by PostgreSQL. The authenticated principal is the audit actor; clients cannot select an arbitrary actor identity. The endpoint exposes the resulting authorized campaign and exact persisted include/exclude scope without introducing scope expansion or assessment execution.

Assessment users cannot self-authorize new campaign scope through this boundary. Campaign creation is intentionally separated from ASSESS so authorization remains an administrative control-plane decision.

Gate 38 is complete after explicit local PostgreSQL-backed `pytest -q` and `ruff check .` validation.

### Architecture Gate 39 — Authenticated Finding Remediation Control API

Gate 39 establishes the authenticated remediation boundary for existing normalized findings. `POST /api/v1/findings/{finding_id}/remediation` requires REMEDIATE permission and accepts only the terminal remediation outcomes MITIGATED or ACCEPTED_RISK with a bounded operator rationale.

Finding remediation transitions are fail-closed at the domain boundary: only a CONFIRMED finding may transition to MITIGATED or ACCEPTED_RISK. The PostgreSQL repository locks the finding row with `FOR UPDATE`, validates the transition, applies the state mutation with a compare-and-set predicate, and records the remediation decision in the same transaction.

Successful changes, idempotent terminal-state requests, and denied invalid transitions are all security-audited with the authenticated principal as actor. Missing findings return 404; invalid target states return 422; invalid remediation transitions return 409.

The endpoint does not alter evidence, create findings, execute providers, change campaign scope, or bypass finding/evidence identity. Validation decisions such as CONFIRMED, FALSE_POSITIVE, and NOT_REPRODUCIBLE remain outside this remediation boundary.

Gate 39 is complete after explicit local PostgreSQL-backed `pytest -q` and `ruff check .` validation.

### Architecture Gate 40 — Authenticated Finding Risk Assessment API — COMPLETE

Gate 40 establishes the authenticated risk decision boundary for an existing normalized finding. `POST /api/v1/findings/{finding_id}/risk-assessments` requires ASSESS permission and invokes the existing deterministic `RiskEngine` with explicitly supplied environmental context.

Environmental context is bounded to normalized 0..1 inputs and requires an explicit source whenever context is supplied. Unknown values remain unknown and are omitted from the weighted calculation; the API never invents exposure, criticality, business impact, threat relevance, exploitability, or control coverage.

PostgreSQL persists the complete deterministic assessment, including context, factors, explanations, inputs used, missing inputs, and context provenance. The assessment record and `RISK_ASSESSMENT_CREATED` audit event are committed atomically with the authenticated principal as the sole audit actor.

The boundary is finding-scoped and read-safe: it does not create findings, mutate evidence, execute providers, alter campaign scope, or introduce a second risk-scoring algorithm. The response exposes the deterministic score, risk level, factor contributions, explanation, provenance, and missing inputs for downstream GUI/reporting use.

Gate 40 implementation includes API regression coverage, deterministic risk-context validation coverage, and PostgreSQL persistence/audit integration coverage. Gate 40 is complete after explicit local PostgreSQL-backed validation.

### Architecture Gate 41 — Authenticated Risk Assessment Read Model API

Gate 41 exposes persisted risk decisions through the authenticated read boundary at `GET /api/v1/findings/{finding_id}/risk-assessments`. The endpoint requires READ permission, verifies that the requested finding exists, and returns bounded assessment history with deterministic ordering and a maximum page size of 100.

The read model exposes only durable risk decision data required by the GUI/reporting layer: assessment identity, finding identity, score, level, environmental context, factor contributions, explanations, inputs used, missing inputs, provenance, and creation time. It does not expose raw evidence, audit records, arbitrary SQL, or provider-internal state.

PostgreSQL reads the canonical `risk_assessments` table with a finding-scoped query and deterministic `created_at DESC, id DESC` ordering. Factor contributions are reconstructed from the persisted score/weight values, preserving the same deterministic calculation without introducing a second risk engine.

Gate 41 implementation includes authenticated read-model regression coverage and bounded PostgreSQL query behavior. Local PostgreSQL-backed `pytest -q` and `ruff check .` are required before Gate 41 can be declared complete.


### Architecture Gate 42 — Durable Attack-Path Relationship Validation Boundary — IMPLEMENTED

Gate 42 establishes the PostgreSQL persistence boundary for explicit attack-path relationships. Relationships are stored separately from findings and require source/target assets plus at least one sealed evidence reference. Newly persisted relationships always begin unvalidated; the persistence layer does not accept client-controlled validation state.

Relationship validation is a separate transactional operation. PostgreSQL locks the relationship row, re-verifies every referenced evidence digest, and requires every referenced evidence item to have a current VALIDATED evidence decision. Only then is the relationship marked validated with the authenticated validator identity and validation timestamp. Re-validating an already validated relationship is an audited no-op.

The mutation and security audit event are committed atomically. The boundary does not infer network reachability, trust, application flow, or authenticated access from asset data, and it does not expose an alternate attack-path algorithm. The existing deterministic AttackPathAnalyzer remains the sole path-analysis engine.

Focused PostgreSQL regression coverage verifies unvalidated creation, asset/evidence integrity, validation fail-closed behavior, audit binding, and idempotent validation.

**Validation status:** Gate 42 implementation and regression tests are committed. Local PostgreSQL-backed `pytest -q` and `ruff check .` are required before Gate 42 can be declared complete.


### Architecture Gate 45 — Authenticated Attack-Path Analysis API — COMPLETE

Gate 45 exposes the existing deterministic attack-path analyzer through an authenticated `POST /api/v1/attack-path/analyze` endpoint requiring ASSESS permission. Entry and objective assets are explicit; duplicate/overlapping inputs are rejected. The API uses only persisted relationships and evidence-backed findings, applies bounded graph/finding/path/hop limits, uses persisted risk assessments without inventing risk scores, and audits successful analysis with the authenticated actor. It returns computed paths without persisting fabricated findings or implying exploitability beyond the supplied validated graph.

**Validation status:** User confirmed local `python -m pytest -q && ruff check .` passed. Gate 45 is complete.

### Architecture Gate 44 — Authenticated Attack-Path Relationship Read Model API — COMPLETE

Gate 44 adds the authenticated `GET /api/v1/attack-path/relations` endpoint. It requires READ permission, uses bounded pagination (1–100 items), deterministic newest-first ordering, and returns only explicit relationship metadata and evidence identifiers. Raw evidence content is not exposed; PostgreSQL remains authoritative.

Local PostgreSQL-backed test and lint validation are required before this gate is complete.

### Architecture Gate 43 — Authenticated Attack-Path Relationship Control API — IMPLEMENTED

Gate 43 exposes explicit attack-path relationship creation and validation through the authenticated API. `POST /api/v1/attack-path/relations` requires ASSESS permission and accepts only a source asset, target asset, enumerated relationship type, and bounded evidence references. The persistence boundary verifies both assets and sealed evidence integrity and always stores the relation as unvalidated.

`POST /api/v1/attack-path/relations/{relation_id}/validate` requires VALIDATE permission. PostgreSQL remains authoritative for row locking, evidence digest verification, current evidence-validation decisions, and atomic security audit persistence. The response is reconstructed from the durable relationship record; client input cannot set validation state or validator identity.

The API does not infer connectivity, trust, or exploitability and does not execute attack-path analysis. The deterministic analyzer continues to consume only explicitly validated, evidence-backed relations.

**Validation status:** Gate 43 implementation and regression tests are committed. Local PostgreSQL-backed `pytest -q` and `ruff check .` are required before Gate 43 can be declared complete.


### Architecture Gate 46 — First Authenticated Dashboard UI Vertical Slice — COMPLETE

Gate 46 introduces the first visible ThreatLens web UI. FastAPI serves the dashboard at `/` and its packaged static assets under `/ui/assets`. The responsive page provides a sign-in form and a read-only operational overview with campaign, asset, service, and finding counts; finding-severity and scan-lifecycle summaries; and bounded recent asset, finding, and scan tables. All operational data is loaded from the existing authenticated API read models. No synthetic findings, evidence, or scan activity are created.

The browser holds the opaque access token in `sessionStorage`, sends it through the Authorization header, and clears it on sign-out or an expired session. The dashboard uses text-only DOM rendering for API values, same-origin requests, a restrictive Content Security Policy, `Cache-Control: no-store` on the HTML page, and security response headers. The static assets are included in the Python package so the UI is available outside a source checkout.

**Validation status:** User confirmed `python -m pytest -q`, `ruff check .`, and `python -m pip wheel . --no-deps -w /tmp/threatlens-dist` passed. Gate 46 is complete.


### Architecture Gate 47 — Durable Login Abuse Protection — IMPLEMENTED

Gate 47 adds a PostgreSQL-backed login-attempt limiter with a 60-second lockout window before password verification. It enforces a maximum of five attempts per normalized username and direct client address per 60-second window, plus a 30-attempt per-client window. PostgreSQL atomic upserts serialize competing attempts across application instances. Only SHA-256 pseudonymous fingerprints of the direct peer and normalized username/address pair are persisted, not the raw identifiers; forwarded client-IP headers are not trusted. Expired buckets are pruned, blocked requests return HTTP 429 with a Retry-After header, and a security audit event is emitted when a bucket first crosses its limit rather than on every blocked request.

Password-hash verification now rejects malformed PBKDF2 encodings, unexpected salt/digest lengths, and iteration counts outside 100,000–1,000,000 before running the expensive derivation. The current 600,000-iteration password hashes remain supported.

**Validation status:** Gate 47 is complete after the user confirmed local PostgreSQL-backed tests, Ruff, and package build checks passed.

### Architecture Gate 48 — Authenticated Security Audit Read Model API — COMPLETE

Gate 48 adds the admin-only, read-only `GET /api/v1/audit-events` endpoint backed by the existing PostgreSQL `audit_events` table. The read model enforces bounded pagination (`limit=1..100`, `offset>=0`), parameterized SQL, deterministic `created_at DESC, id DESC` ordering, and an ordering index. Its explicit response allowlist excludes free-text event details and secret-bearing fields. API regression tests cover authentication, ADMIN authorization, pagination bounds, empty pages, and response-field allowlisting; PostgreSQL integration tests cover empty results, deterministic ordering, pagination, and detail omission.

**Validation status:** User confirmed 33 focused API/PostgreSQL integration tests passed, the full pytest suite passed, `ruff check .` passed, `git diff --check` passed, and the package wheel built successfully. Five existing Starlette deprecation warnings were reported during the full suite; they did not fail validation.


### Architecture Gate 52 — Execution-Lease-Fenced Evidence and Finding Persistence — COMPLETE

PostgreSQL execution-bound evidence and finding writes lock the authoritative scan row, require the execution to remain RUNNING, and persist under the same transaction. The production repository declares execution fencing mandatory; ProviderHandoff and DurableFindingCorrelator fail closed when a fenced method is unavailable, and generic PostgreSQL evidence writes reject execution-bound evidence.

**Validation status:** On 2026-10-14, the user confirmed the full suite reached 100% with no skip summary, the PostgreSQL-backed regression tests executed, Ruff passed, diff checks were clean, and the package wheel built successfully. Five Starlette deprecation warnings were non-failing.

### Architecture Gate 53 — Durable Finding Remediation Idempotency — COMPLETE

The authenticated finding-remediation API requires a bounded `Idempotency-Key`. PostgreSQL persists the actor/key-scoped request fingerprint and original result atomically with the remediation transition and audit event. Exact retries replay without duplicate audit events; conflicting key reuse returns HTTP 409.

**Validation status:** On 2026-10-14, 9 focused API tests and 5 focused PostgreSQL tests passed; the full suite, Ruff, diff checks, and package wheel build also passed.


### Architecture Gate 57 — Fail-Closed Audit Protection Drift Detection

PostgreSQL startup verifies the required row-level UPDATE/DELETE trigger and statement-level TRUNCATE trigger using catalog event bits, enabled state, and expected trigger-function identity. It fails closed when a trigger is missing, disabled, or structurally altered. The verifier also compares the normalized function body with the expected unconditional fail-closed implementation; marker-string presence alone is not accepted as proof of behavior. Startup does not repair drift automatically. Gate 57 validation of the final function-body hardening passed on 2026-10-14; see the completed Gate 57 status above.


### Architecture Gate 59 — Fail-Closed Runtime Database Privilege Verification: COMPLETE

API startup verifies effective runtime database privileges after read-only schema readiness checks. It rejects superuser identities, database/schema CREATE authority, audit mutation/trigger privileges, migration-registry mutation privileges, and ownership or membership in protected-object owner roles. PostgreSQL integration tests cover a least-privilege login, direct schema CREATE, inherited DDL role membership, protected-table mutation rights, and API connection cleanup on privilege-check failure.

**Validation status:** On 2026-10-14, the user confirmed 43 focused PostgreSQL migration/runtime-privilege/API tests passed, the full PostgreSQL-backed suite reached 100% without a reported failure or skip summary, Ruff and diff checks passed, and the package wheel built successfully on main commit `78f7856677d029c2f01d0000831b080e16c8f45c`. Wheel SHA-256: `f5315fe6366d53d9607e11aa1f4624978266c3e29a75376377bd17d03d63bb71`. Five Starlette deprecation warnings were non-failing.

Gate 59 closed a key gap by verifying protected-object privileges, but its owner checks did not enumerate all application-schema relations and routines. Gate 60 extends the same fail-closed startup boundary to reject ownership of any application-schema relation, routine, or type, including ownership inherited through role membership. It preserves the separate migration identity and does not add DDL to API startup.

**Gate 60 validation status: COMPLETE.** On 2026-10-14, the user confirmed the required PostgreSQL-focused tests, full PostgreSQL-backed suite, Ruff, diff check, and wheel build were clean and successful on main revision `080cc28ee38a207f3a5da83f36497510495a4a1a`.

### Architecture Gate 61 — Fail-Closed Runtime Relation Privilege Verification: COMPLETE

Gate 60 verifies ownership but does not detect high-impact relation privileges granted to a non-owner runtime role. Gate 61 extends the same startup check across ordinary and partitioned application tables and fails closed when the effective runtime/session identities have TRUNCATE, TRIGGER, or REFERENCES privilege, including privileges inherited through role membership. It preserves application DML, existing audit/migration registry protections, and read-only API startup. PostgreSQL regression tests grant each privilege independently on an ordinary `assets` table and require startup verification to reject it.

**Gate 61 validation status: COMPLETE.** On 2026-10-14, the user confirmed all focused PostgreSQL migration/runtime privilege/API tests, the full PostgreSQL-backed suite, Ruff, diff check, and wheel build completed cleanly on main revision `0c6f22281f3242187ec2c1b3165b50557d9665d1`.

### Architecture Gate 62 — Fail-Closed Runtime Sequence Privilege Verification: COMPLETE

Application IDs are UUID-backed, so the runtime identity has no expected need to read or mutate PostgreSQL sequences. Gate 62 enumerates application-schema sequences and rejects effective SELECT, USAGE, or UPDATE privileges for either `current_user` or `session_user`, including inherited grants. The check is read-only, retains the separate migration identity, and adds real PostgreSQL regressions for each sequence privilege while confirming a least-privilege runtime login still passes.

### Architecture Gate 63 — Fail-Closed SECURITY DEFINER Routine Execution Verification: COMPLETE

The runtime privilege verifier now rejects an effective EXECUTE grant on any SECURITY DEFINER routine in the active application schema for either `current_user` or `session_user`, including grants inherited through roles or granted to PUBLIC. This closes a privilege-escalation path where a callable elevated routine could execute with its owner's authority. The change preserves ordinary invoker-security routines and the separate migration identity. A PostgreSQL integration test creates a SECURITY DEFINER routine and verifies fail-closed rejection for a genuine runtime login. The user confirmed Gate 63 clean and successful on 2026-10-14.


### Architecture Gate 64 — Authenticated SOC Workspace Read-Model Expansion: COMPLETE

Expose the existing authenticated campaign, evidence, attack-path relationship, and administrator-only audit read models in the dashboard. Render persisted API data only, preserve evidence hashes and validation state, and handle role-restricted audit access safely.


### Architecture Gate 65 — Professional SOC Workspace Navigation & Accessibility: COMPLETE

The workspace now contains the existing authenticated SOC read models, but its active navigation state is click-driven rather than scroll-aware. Gate 65 synchronizes the active navigation item with the visible section, adds keyboard-visible focus treatment, and respects reduced-motion preferences while preserving the restrictive CSP and existing API contracts. The user confirmed Gate 65 clean and successful on 2026-10-14; this is user-confirmed validation, not an independently executed local test result.


### Architecture Gate 66 — Fail-Closed Runtime User-Identity Mutation Privilege Verification: COMPLETE

The runtime privilege verifier rejects effective table-level INSERT, UPDATE, and DELETE on the authentication `users` table. Identity provisioning belongs to a trusted deployment/admin workflow. The user confirmed Gate 66 clean and successful on 2026-10-14; this is user-confirmed validation.

### Architecture Gate 67 — Fail-Closed Runtime Column-Level User-Identity Mutation Privilege Verification: COMPLETE

The runtime startup verifier rejects effective column-level INSERT or UPDATE grants on the authentication `users` table for `current_user` or `session_user`, including inherited/PUBLIC grants. The user confirmed Gate 67 clean and successful on 2026-10-14; this is user-confirmed validation.

### Architecture Gate 68 — Fail-Closed Handling of Invalid Persisted User Roles: COMPLETE

Unsupported or malformed persisted roles use the established generic authentication/session failure paths. Login writes a denied audit event with a fixed non-sensitive detail and does not create a session when the stored role is invalid. The user confirmed Gate 68 clean and successful on 2026-10-14; this is user-confirmed validation.

### Architecture Gate 69 — Fail-Closed Handling of Corrupt Persisted Session Records: COMPLETE

Session authentication maps malformed persisted expiry timestamps and UUID identifiers to the existing generic invalid-session response, while preserving explicit inactive-user behavior and allowing infrastructure failures to propagate. The user confirmed Gate 69 clean and successful on 2026-10-14; this is user-confirmed validation.

### Architecture Gate 70 — Atomic Login Session and Success-Audit Persistence: COMPLETE

Successful login persists the authentication session and corresponding success audit event in one repository transaction. If audit insertion fails, the transaction rolls back session creation. SQLite and PostgreSQL regression tests inject audit failures and verify rollback. On 2026-10-14, the user confirmed focused API tests, the full PostgreSQL-backed suite, Ruff, diff check, package wheel build, and final main synchronization were clean. Five Starlette deprecation warnings were non-failing; the optional `python -m build` command was unavailable, so the established pip wheel build was used.

### Architecture Gate 71 — Atomic Logout Session Revocation and Success-Audit Persistence: COMPLETE

Logout routes through a dedicated repository operation that revokes the session and writes the LOGOUT success audit event in one transaction for PostgreSQL and SQLite compatibility paths. Failure-injection regressions verify audit-write failure rolls back revocation and successful logout records the audit event. On 2026-10-14, the user confirmed Gate 71 clean and successful. This is user-confirmed validation.

### Architecture Gate 72 — Atomic User Provisioning and Success-Audit Persistence: COMPLETE

AuthenticationService.create_user() delegates to save_user_with_audit(), which persists the new user and USER_CREATED success event in one transaction in PostgreSQL and SQLite compatibility storage. Failure-injection regressions assert that an audit-write failure rolls back user creation. API test doubles implement the atomic user-and-audit contract. On 2026-10-19, the user confirmed 20 focused auth/storage tests passed and the full PostgreSQL-backed suite passed with 309 passed, 0 skipped, and 5 non-failing Starlette deprecation warnings. Ruff, `git diff --check`, and package wheel build passed. Wheel SHA-256: `eb66201f4e2622b35d262e399e12df464b58b014011be7ab54ac167575e98f49`. Validation was user-confirmed.

### Architecture Gate 73 — Atomic Login Rate-Limit Threshold Audit Persistence: COMPLETE

The PostgreSQL login-attempt repository operation accepts threshold metadata and writes the `LOGIN_RATE_LIMITED` audit event in the same transaction as the corresponding counter update. The login API no longer inserts the threshold audit event separately. On 2026-10-21, the user confirmed focused PostgreSQL/API tests and the full PostgreSQL-backed suite passed on Windows with Python 3.15; Ruff and `git diff --check` passed; and `pip wheel` built successfully. Five Starlette deprecation warnings were non-failing. Wheel SHA-256: `ae82526e8bffef66a9e426f99ff20a2c5199091579aa32b644273a7bc234a565`. These are user-confirmed local results; no GitHub push was made.

### Architecture Gate 74 — Python 3.15 Windows Dependency-Install Compatibility: COMPLETE

A clean Python 3.15 Windows install exposed a PyYAML source-build failure in the `uvicorn[standard]` dependency chain when Microsoft C++ Build Tools are absent. The project now depends on Uvicorn core because the application does not use the optional standard extras' YAML configuration, reload, or alternative HTTP/WebSocket implementations. A clean Python 3.15 install, project wheel build, clean-environment imports with PyYAML absent, Ruff, and diff check passed. The user confirmed the full PostgreSQL-backed test suite passed with no skip summary; five Starlette deprecation warnings were non-failing.

### Architecture Gate 75 — Evidence-Backed Campaign Report Export: COMPLETE

Gate 75 adds a READ-authorized JSON report download for one campaign. The report is assembled from PostgreSQL records scoped through that campaign's persisted scan execution IDs and evidence provenance. It includes campaign scope, scan counts, finding summaries/details, latest persisted risk assessments, and evidence references with integrity hashes; raw evidence content is excluded. Results are bounded to 500 findings and 20 evidence references per finding with truncation indicators. The dashboard exposes a campaign selector and download action. The user confirmed the report-specific PostgreSQL integration test, full PostgreSQL-backed test suite, Ruff, diff check, and Windows wheel build passed on 2026-10-21. Five Starlette deprecation warnings were non-failing.

### Architecture Gate 76 — Auditable Campaign Report Export: COMPLETE

The report endpoint records `CAMPAIGN_REPORT_EXPORTED` with the authenticated actor, campaign identifier, and bounded report summary in the same transaction as report assembly. Audit persistence failure returns a generic 503 without report data. API and PostgreSQL regressions cover success attribution, fail-closed behavior, and missing campaigns. No schema migration was needed. On 2026-10-21, the user confirmed the focused API/PostgreSQL tests and full suite reached 100%; Ruff and diff check passed; and the Windows wheel built successfully. Five Starlette deprecation warnings were non-failing.

### Architecture Gate 77 — Secret Redaction in Evidence Metadata: IN PROGRESS

The evidence-list response redacts secret-like metadata fields and sanitizes URL-like values by removing userinfo, query strings, and fragments. Stored evidence and hashes remain unchanged; safe provenance such as provider and execution ID remains available. Focused evidence API coverage is added; local Windows validation remains pending.
