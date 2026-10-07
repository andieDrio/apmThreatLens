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

Architecture Gate 34: Authenticated Scan Lifecycle Control API. Gate 20 PostgreSQL Transactional Concurrency and Failure-Recovery Hardening is complete after local validation. PostgreSQL is now the sole active development/test persistence path; the legacy SQLite adapter is not used by the application or active test suite. Gate 18 Reliability and Performance remains complete with durable heartbeat leases, explicit authenticated stale recovery, bounded provider concurrency, compare-and-set lifecycle transitions, atomic persistence/audit mutations, and explicit handling of non-cooperative provider timeouts.

### Gate 19 PostgreSQL Enforcement — COMPLETE

The active persistence test suite now runs through PostgreSQL only. The shared integration fixture requires `THREATLENS_TEST_DATABASE_URL` or the canonical `THREATLENS_DATABASE_URL`, never falls back to SQLite, initializes the schema, isolates tests with `TRUNCATE ... CASCADE`, and covers domain persistence, foreign-key integrity, authentication, durable correlation, evidence validation, scan lifecycle CAS, concurrency-sensitive orchestration, and PostgreSQL trigger-based failure-atomicity scenarios. The repository contains no active test-suite imports of `SQLiteRepository`. The SQLite adapter is retained only as legacy compatibility code and receives no new production behavior.

### PostgreSQL Deployment Readiness

PostgreSQL is the permanent and canonical deployment persistence target. The repository includes a PostgreSQL adapter and `.env.example`; local database installation and credentials remain deployment-environment responsibilities. The application does not auto-start or auto-create a database server.

For local development, install the Python dependencies after pulling the repository and configure `THREATLENS_DATABASE_URL` from `.env.example` without committing secrets.

### Architecture Gate 26 — Vulnerability Correlation Context Expansion — IMPLEMENTED

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


### Architecture Gate 25 — Evidence-Backed Vulnerability Finding Enrichment — IMPLEMENTED

Gate 25 connects trusted vulnerability intelligence to an existing normalized finding without creating unsupported findings. Enrichment requires a deterministic vulnerability match and the intelligence record's evidence references must be present in the same ProviderHandoff input. The resulting finding preserves the original evidence, adds trusted intelligence evidence, applies normalized vulnerability identity/CVE/CWE/CVSS/severity metadata, and remains subject to the normal ProviderHandoff validation and durable correlation boundary.

The enrichment layer is network-free and cannot fetch intelligence, infer affected versions, or bypass evidence requirements. Intelligence-backed metadata is therefore an evidence-supported augmentation of an existing finding rather than an assertion that a service is exploitable.

**Validation status:** Gate 25 includes focused regression tests but requires local pytest -q and ruff check . execution before it may be declared complete.


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


### Architecture Gate 33 — Campaign & Scope Read Model API — IMPLEMENTED

Gate 33 establishes the authenticated GUI-facing campaign and authorization-scope read model at `GET /api/v1/campaigns`. The endpoint requires READ permission and returns bounded campaign identity, authorization state, lifecycle state, creation time, and the explicit include/exclude scope entries.

PostgreSQL uses fixed SQL with a maximum page size of 100 and deterministic ordering. Scope is read directly from the persisted authorization boundary; the API does not infer targets, expand ranges, or normalize scope into newly authorized destinations. The endpoint is read-only and excludes credentials, evidence content, audit records, arbitrary SQL, and campaign mutation.

**Validation status:** Gate 33 focused API regression tests are implemented. Local `pytest -q` and `ruff check .` are required before the gate can be declared complete.

### Architecture Gate 32 — Scan Read Model API — COMPLETE

Gate 32 establishes the authenticated GUI-facing scan execution read model at `GET /api/v1/scans`. The endpoint requires READ permission and returns bounded execution metadata including campaign identity, provider, lifecycle state, queue/start/finish timestamps, heartbeat state, and a bounded error summary when present.

PostgreSQL uses fixed SQL with a maximum page size of 100 and deterministic ordering. The endpoint is read-only and excludes raw evidence, credentials, audit records, arbitrary SQL, and provider-internal execution details. It exposes operational state only; it does not mutate scan lifecycle state or bypass orchestration authorization.

**Validation status:** Gate 32 focused API regression tests are implemented. Local `pytest -q` and `ruff check .` are required before the gate can be declared complete.

### Architecture Gate 31 — Asset & Service Read Model API — COMPLETE

Gate 31 establishes the authenticated GUI-facing attack-surface inventory contract at `GET /api/v1/assets`. The endpoint returns bounded asset identity and explicitly observed service metadata, including protocol, port, service name, and version. Pagination is capped at 100 records per request.

The read model uses fixed PostgreSQL queries and deterministic ordering. It does not expose arbitrary SQL, raw evidence, credentials, audit records, or unrestricted database rows. Service data is presented as observation context for the asset inventory; it does not itself assert vulnerability or exploitability.

**Validation status:** Gate 31 focused API regression tests are implemented. Local `pytest -q` and `ruff check .` are required before the gate can be declared complete.
