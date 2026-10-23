# Advanced VAPT System Architecture

## 1. Architectural Goal

APM ThreatLens is a security assessment orchestration platform for explicitly authorized VAPT campaigns. It is not a collection of loosely connected scanners.

The architecture must preserve a clear separation between:

- campaign and scope control
- asset and service inventory
- provider execution
- normalized findings
- evidence
- vulnerability intelligence
- risk analysis
- attack paths
- validation
- remediation
- reporting

## 2. Core Flow

TARGET
→ SCOPE
→ DISCOVERY
→ ENUMERATION
→ ASSESSMENT
→ VALIDATION
→ CORRELATION
→ RISK ANALYSIS
→ ATTACK PATH ANALYSIS
→ EVIDENCE COLLECTION
→ REMEDIATION
→ REPORTING
→ VERIFICATION

## 3. Initial Domain Boundaries

The foundational domain model must support at minimum:

- Local user and role
- Campaign
- Scope
- Target
- Asset
- Service
- Provider
- Scan
- Finding
- Evidence
- Vulnerability
- Risk
- Attack Path
- Remediation
- Validation
- User
- Role
- Audit Event

## 4. Provider Boundary

Providers must be accessed behind interfaces. Examples:

- DiscoveryProvider
- NetworkScannerProvider
- WebScannerProvider
- APIScannerProvider
- TLSScannerProvider
- VulnerabilityProvider
- ConfigurationProvider
- ThreatIntelProvider
- EvidenceProvider

Provider output must be normalized before entering correlation and risk analysis.

## 5. Safety Boundary

Assessment execution must be constrained by:

- explicit campaign scope
- target allowlist
- exclusion list
- authorization state
- rate limits
- concurrency
- timeout
- safe-mode defaults
- destructive-operation restrictions
- cancellation
- auditability

No destructive operation is the default.

## 6. Evidence Boundary

Raw evidence and normalized interpretations are separate concepts. Findings must retain provenance and preserve enough evidence to support later validation and reporting.

Synthetic telemetry must never be represented as real evidence.

Provider handoff seals raw evidence with a deterministic SHA-256 digest. Evidence is bound to execution ID and provider metadata before persistence. A normalized finding must reference evidence supplied by the same handoff and must match the supplied asset. Provider output cannot be persisted as a finding without evidence references.

## 7. Risk Boundary

Risk must be explainable and must not depend exclusively on CVSS. Environmental context, exploitability, exposure, asset criticality, business impact, threat relevance, control coverage, and confidence are relevant inputs.

## 8. Data Integrity

Use explicit identifiers, lifecycle states, timestamps, provenance, and database/application constraints appropriate to the selected persistence technology. Correlation must remain deterministic and auditable.

PostgreSQL is the canonical and permanent persistence implementation through `PostgresRepository`, using the domain repository methods and production integrity constraints. SQLite is not a production persistence backend; any retained SQLite code exists only for legacy/unit-test compatibility and must not define production behavior or introduce a second runtime persistence path. PostgreSQL connection details are deployment configuration; the application does not auto-start or auto-create a database server.

## 9. Campaign / Scan Orchestration

Campaign execution is represented by a persisted Scan with a unique execution ID and provider identity. Lifecycle transitions are fail-closed:

QUEUED → RUNNING → COMPLETED | FAILED | CANCELLED | PARTIAL

A queued execution may also be cancelled before provider execution. Terminal states cannot transition again. The orchestrator validates authorization and execution policy before queueing, persists lifecycle changes, isolates provider execution behind a protocol, and passes a cancellation event to the provider.

The persistence layer is authoritative for lifecycle state; orchestration must not infer completion solely from in-memory execution.

## 10. Provider Execution and Observability

Providers are explicitly registered through a ProviderRegistry. Each registration declares a stable provider name, version, capabilities, and whether the provider is safe-by-default. Registry identity must match the executor identity and duplicate registrations are rejected.

Provider execution is wrapped by an ExecutionRuntime that creates an execution context and emits structured events for STARTED, PROGRESS, EVIDENCE, FINDING, WARNING, ERROR, and COMPLETED/CANCELLED outcomes. Every event carries the execution ID and provider identity. Runtime metrics include duration, event count, evidence count, and finding count.

Provider failures are captured as structured execution errors. The runtime applies the configured execution timeout as a cooperative cancellation boundary: on timeout it signals the provider cancellation event and records a timeout error. Provider implementations that launch external processes must terminate those processes when the cancellation event is set; the runtime must not pretend that a Python thread can forcibly kill arbitrary provider work.

The orchestration layer can execute only providers selected from the explicit registry through the registered-provider path. This prevents direct, untracked scanner invocation from bypassing provider metadata and observability.

## 11. Evidence and Finding Handoff

Provider output crosses into the domain through an explicit handoff boundary. Raw evidence is immutable at the domain level and is sealed with SHA-256 over its exact content. The handoff binds execution ID, provider name, and provider version into evidence metadata while preserving the provider as the evidence source.

Normalized findings remain separate from raw evidence. A finding must reference at least one evidence item, must belong to the supplied asset, and must carry the provider as its detection source. The handoff rejects mismatched asset identity, missing evidence references, and tampered evidence digests. This establishes the minimum provenance contract required for later multi-provider correlation and validation.

## 12. Controlled Discovery

The first discovery provider is deliberately non-networking. `DiscoveryProvider` consumes only the targets already present in an authorized campaign scope, normalizes IPv4, IPv6, FQDN, and explicit HTTP/HTTPS URL identifiers, applies the campaign exclusion set, persists normalized assets, and records discovery-target evidence through the provider handoff.

Gate 06 must not expand scope through discovered data. It must not probe the network, claim vulnerabilities, or bypass the provider runtime. Cancellation is checked before processing each target. This establishes the safe discovery-to-asset/evidence pattern before an active network enumeration adapter is introduced.

## 13. Controlled Network Discovery

Gate 07 introduces `NetworkDiscoveryProvider` for active but bounded TCP connection discovery. The provider accepts only explicitly listed IP addresses or FQDNs already contained in the authorized campaign scope. URL targets, path-bearing values, CIDR expansion, UDP probing, arbitrary port ranges, and exploitation are rejected or excluded from this adapter.

The execution policy bounds the target count, explicit port set, and per-connection timeout. The provider checks cancellation before each target and port. Positive TCP observations create normalized `Service` records and raw `tcp-connect` evidence; they do not create vulnerability findings. Service exposure is therefore kept distinct from vulnerability assessment.

The TCP adapter uses a minimal connection attempt and sends no application payload. A future scanner backend must preserve the same authorization, exclusion, timeout, cancellation, evidence, and provider-runtime boundaries.

## 14. Service Identification and Protocol Metadata Normalization

Gate 08 establishes a bounded observation-normalization layer in `providers/identification.py`. `normalize_observation()` accepts an explicit port plus an optional bounded banner/protocol observation and returns a `ServiceObservation` containing protocol, service name, product, version, confidence, and the retained banner observation.

Protocol classification uses explicit provider protocol data when supplied and otherwise applies conservative port/banner heuristics. HTTP `Server` headers and SSH identification strings may provide product/version metadata. Unknown explicit protocols remain `UNKNOWN` rather than being guessed. Banners are bounded to 8192 characters and NUL bytes are removed before parsing.

This layer performs classification only. It does not claim CVEs, exploitability, compromise, or vulnerability. The normalized observation must remain traceable to the provider evidence that produced the banner/protocol input. Active banner interrogation is intentionally deferred to the next gate so network probing and application-payload behavior remain behind explicit execution controls.

## 15. Controlled Active Service Interrogation

Gate 09 introduces `ActiveServiceInterrogationProvider` for a tightly bounded set of protocol-specific observations against explicitly scoped hosts. The provider does not accept arbitrary payloads. Version 1 supports only receive-oriented SSH/SMTP banner collection and a fixed HTTP `HEAD /` request on TCP/80. HTTPS, arbitrary application payloads, UDP, CIDR expansion, and exploit attempts remain outside this gate.

The execution policy bounds the target count, explicit port set, per-probe timeout, and maximum response size. Exclusions are applied before probing, cancellation is checked before every probe, and invalid host/path-bearing targets are rejected. Raw responses are preserved as `service-interrogation` evidence and passed through the existing ProviderHandoff for SHA-256 sealing and execution/provider provenance.

The provider may invoke the existing identification normalizer to attach protocol/product/version metadata to evidence. It does not create normalized vulnerability findings. A positive protocol response is still an observation, not proof of a vulnerability. Any future authenticated or intrusive application interaction must receive a separate architecture gate with stronger authorization and safety controls.

## 16. TLS Assessment and Transport-Security Normalization

Gate 10 introduces `TLSAssessmentProvider` for bounded TLS inspection against explicitly authorized, in-scope host/IP targets. The default execution policy limits assessment to TCP/443 and TCP/8443, with a maximum of 16 targets and a per-connection timeout. Exclusions and cooperative cancellation are enforced before each probe.

The TLS probe uses the platform TLS stack with normal certificate verification enabled. Successful observations preserve negotiated TLS version, cipher, certificate subject, issuer, SAN values, validity timestamps, and hostname-verification state. Certificate verification failures are preserved as transport evidence rather than being silently converted into a vulnerability claim. Network/time-out failures do not fabricate observations.

Raw TLS observations are serialized as `tls-assessment` evidence and passed through the existing ProviderHandoff for SHA-256 sealing and execution/provider provenance. The provider does not create normalized vulnerability findings. Policy evaluation of weak TLS versions, deprecated ciphers, certificate expiration, hostname mismatch, or other transport weaknesses belongs to a subsequent assessment layer with explicit finding criteria and evidence requirements.

## 17. TLS Security Policy Evaluation and Finding Integration

Gate 11 introduces deterministic TLS security-policy evaluation and closes the first end-to-end observation-to-finding path. `evaluate_tls_observation()` is a network-free policy function: it accepts an already captured `TLSObservation`, an asset ID, and the exact evidence ID that triggered the evaluation. Rules cover certificate validation failure, hostname mismatch, expired certificates, deprecated TLS 1.0/1.1, and weak/deprecated cipher markers. Healthy observations produce no finding.

The TLS provider persists and seals the raw `tls-assessment` evidence first. When an asset resolver is explicitly supplied, the provider resolves the authorized asset, evaluates the observation against the policy, and sends every resulting finding back through `ProviderHandoff.persist_finding()`. The handoff therefore validates asset identity, requires the exact persisted evidence reference, and binds the provider source before repository persistence.

The integration is deliberately fail-closed when finding generation is enabled but the target cannot be resolved to an asset: it raises an error rather than creating an orphan finding. Without an asset resolver, the provider remains evidence-only, preserving compatibility for isolated observation tests. This gate does not perform network access inside the policy engine, does not fabricate findings, and does not bypass repository boundaries.

## 18. PostgreSQL Deployment Boundary

PostgreSQL is the permanent production persistence backend through `PostgresRepository`. The schema mirrors the current domain integrity requirements: foreign keys, unique canonical asset identity, service uniqueness per asset/protocol/port, finding/evidence relationships, scan execution identity, and bounded CVSS/confidence values.

The PostgreSQL app runtime registers the built-in TCP discovery and HTTP(S) baseline providers. `GET /api/v1/providers` exposes only registered provider metadata. `POST /api/v1/campaigns/{campaign_id}/scans/run` loads a campaign from the personal workspace, applies durable scan-command idempotency, claims the queued execution with a QUEUED-to-RUNNING compare-and-set, executes through the bounded provider runtime, and finalizes via the existing audited lifecycle transition. Exact retries can claim a still-QUEUED execution after interruption; concurrent retries cannot both claim it. The queue-only `/scans` endpoint remains available for a separate local worker.

TCP scope accepts a bare host/IP (bounded default ports) or one explicit endpoint such as `192.0.2.10:8443` or `[2001:db8::10]:8443`; explicit endpoints probe only that port. HTTP assessment accepts absolute HTTP(S) URLs, limits requests to HEAD by default, suppresses redirects, bounds response reads, and blocks private/reserved destinations by default. These are conservative observation tools and do not run exploit payloads or call external Nmap/Nikto executables. The synchronous run endpoint is intended for these bounded local-development scans; durable multi-process worker handoff remains separate work.

The repository contains `.env.example` with separate `THREATLENS_DATABASE_URL` (runtime) and `THREATLENS_MIGRATION_DATABASE_URL` (controlled schema migration) templates. Real credentials must remain outside version control. Local PostgreSQL installation, service lifecycle, database creation, and credential provisioning are deployment responsibilities and must not be silently automated by the application. API startup verifies schema readiness without applying DDL; run `python -m threatlens.storage.migrate` separately with the migration identity.

## 19. Security

The platform itself is security-sensitive. Apply authentication, authorization, least privilege, secure secret handling, strict validation, output encoding, parameterized persistence operations, SSRF protections, path protections, secure command-execution boundaries, and comprehensive audit logging.

## 20. Architecture Gate 01

Establish the minimal production-grade backend/domain contract foundation required for later orchestration and provider implementations, without introducing fake scanner results or premature coupling to any one security tool.

## 21. Architecture Gate 02

Establish the persistent data-integrity boundary for Campaign → Scope → Asset → Service → Finding → Evidence. PostgreSQL is the canonical implementation of this boundary. Any retained SQLite adapter is legacy/unit-test compatibility only; provider execution and higher-level orchestration must depend on repository contracts rather than direct SQL access.

## 22. Architecture Gate 03

Establish the campaign/scan orchestration boundary with execution IDs, explicit lifecycle transitions, cancellation semantics, provider isolation, and persisted authoritative execution state. Actual scanner/provider implementations remain out of scope for this gate.

## 23. Architecture Gate 04

Establish provider registration, capability metadata, execution context, structured execution events, runtime metrics, provider failure capture, and cooperative timeout/cancellation signaling. Real scanner integrations remain out of scope until evidence/finding handoff contracts are established.

## 24. Architecture Gate 05

Establish the evidence/finding handoff boundary: immutable evidence sealing, content integrity, execution/provider provenance, evidence-backed normalized findings, asset identity validation, and rejection of findings that cannot be traced to supplied evidence.

## 25. Architecture Gate 06

Establish the first controlled discovery provider. The initial implementation must normalize explicitly scoped targets, honor exclusions and cancellation, persist assets with deterministic canonical identity, and preserve discovery evidence/provenance without performing network probing or generating vulnerability claims.

## 26. Architecture Gate 07

Establish the controlled network discovery adapter. The implementation must perform only bounded TCP connection discovery against explicitly scoped IP/FQDN targets, enforce exclusions and target/port/time limits, honor cancellation, normalize positive services, preserve raw evidence/provenance, and never convert service exposure into a vulnerability claim. PostgreSQL deployment readiness is included as a persistence backend so later backend deployment does not require a storage-contract rewrite.

## 27. Architecture Gate 08

Establish service identification and protocol metadata normalization over bounded provider observations. The implementation must normalize protocol, service, product, version, and confidence without unsupported guessing; preserve bounded raw banner context; remain evidence-traceable; and keep service identification separate from vulnerability assessment. Active application-payload interrogation remains behind the next explicit execution gate.

## 28. Architecture Gate 09

Establish evidence-backed active service interrogation. The implementation must permit only explicit, protocol-specific safe probes against authorized in-scope hosts; enforce exclusions, target and port allowlists, timeout, response-size, and cancellation limits; preserve raw responses through the evidence handoff; and avoid arbitrary payload execution, exploitation, or automatic vulnerability claims. Initial supported probes are SSH/SMTP banner reads and fixed HTTP `HEAD /` on TCP/80. HTTPS, UDP, authenticated application workflows, and intrusive testing require separate architecture gates.

## 29. Architecture Gate 10

Establish bounded TLS assessment and transport-security normalization. The implementation must perform TLS inspection only against explicitly authorized in-scope hosts, enforce exclusions, target/port/time limits and cancellation, preserve negotiated protocol/cipher and certificate metadata as evidence, retain certificate verification failures without fabrication, and keep transport observations separate from vulnerability findings. Weak-version, weak-cipher, expiration, hostname-mismatch, and related security-policy conclusions require a subsequent explicit assessment layer with evidence-backed finding criteria.

## 30. Architecture Gate 11

Establish deterministic TLS security-policy evaluation and end-to-end finding integration. The policy layer must be network-free and deterministic; every finding must reference the exact persisted evidence that triggered it and the authorized asset being assessed. The TLS provider must persist evidence before evaluating findings, resolve the target to an asset before finding persistence, and use the existing ProviderHandoff rather than writing findings directly to storage. Missing asset resolution must fail closed when finding integration is enabled. Evidence-only execution remains supported when no resolver is configured for isolated observation workflows.

## 31. Architecture Gate 12

Establish deterministic cross-provider finding correlation and deduplication before later risk aggregation. correlation_key() derives logical identity from asset identity plus vulnerability ID, or normalized title/CWE when no vulnerability identifier exists. correlate_findings() collapses equivalent findings into one stable UUIDv5 logical finding, preserves every unique evidence reference, retains contributing provider sources, and selects the strongest supported severity/state/confidence without fabricating technical context.

Correlation is deliberately conservative because the current Finding domain contract does not yet model endpoint, parameter, or service-location identity. The engine never infers equivalence across different assets or unsupported location dimensions, and the pure correlation layer performs no network access or persistence.

## 31. Architecture Gate 12

Gate 12 establishes deterministic, provider-independent correlation as a pure normalization layer. A correlation key is derived from authorized asset identity plus vulnerability ID, or asset identity plus normalized title/CWE when no vulnerability ID exists. Correlation unions unique evidence references, preserves contributing sources, selects the strongest severity/confidence, and never correlates findings from different assets.

## 32. Architecture Gate 13

Gate 13 makes finding correlation durable at the persistence boundary. DurableFindingCorrelator assigns the deterministic logical finding ID before first persistence, stores a unique finding_correlations key-to-finding mapping, and routes subsequent provider findings through the same logical record. Existing findings are updated using the correlation result while evidence relationships are unioned with duplicate-safe inserts.

ProviderHandoff remains the only provider-facing finding boundary: after asset/evidence validation, it optionally delegates to the durable correlator rather than allowing providers to write correlated records directly. SQLite and PostgreSQL repositories expose the same correlation primitives. Raw evidence is never modified by correlation. A repository restart therefore retains the logical finding identity and prevents the same provider-independent weakness from becoming a new logical finding.

The current gate does not infer endpoint, parameter, service-location, or application-context equivalence because those dimensions are not yet represented in the Finding domain contract. Correlation remains deliberately conservative until those fields are introduced by a later architecture gate.


## 33. Architecture Gate 14

Gate 14 establishes the Explainable Risk Engine over already-normalized and, where applicable, durably correlated findings. RiskEngine is a network-free deterministic policy component. It consumes the finding's technical severity and confidence plus explicit environmental context for exploitability, exposure, asset criticality, business impact, threat relevance, and control coverage.

The weighted risk model uses technical severity (20%), exploitability (15%), exposure (15%), asset criticality (15%), business impact (15%), threat relevance (10%), and finding confidence (10%). If CVSS is present and no explicit exploitability value is supplied, CVSS may provide the exploitability signal, but CVSS is never the complete risk score. Control coverage is a separate mitigation factor and can reduce residual risk by at most 50% of its normalized coverage value.

Unknown environmental inputs are not treated as zero. They are excluded from the weighted calculation and reported in missing_inputs, preventing the engine from fabricating low exposure, low business impact, or effective controls. Every RiskAssessment retains factor-level scores, weights, rationale, source inputs, missing inputs, a deterministic normalized score, and a Critical/High/Medium/Low/Informational level.

The engine performs no network access, scanner execution, provider calls, database writes, or unsupported threat inference. It operates only on the evidence-backed Finding contract and explicit context supplied by a higher orchestration layer. This preserves the provider, persistence, and evidence boundaries established by earlier gates while making prioritization auditable and explainable.


## 34. Architecture Gate 15

Gate 15 establishes deterministic attack-path analysis over correlated findings and explicit asset relationships. The new attack-path boundary does not discover network topology, infer trust, assume exploitability, or treat adjacent assets as reachable merely because they share a network or service attribute.

AttackPathRelation requires a source asset, target asset, explicit relationship type, and at least one evidence reference. Relationships are directional and must be explicitly marked validated before the analyzer can traverse them. Relationship identity is deterministic from its endpoints, type, and evidence references. Unvalidated relationships and relationships lacking evidence are excluded or rejected rather than converted into attack-path claims.

AttackPathAnalyzer accepts explicit entry assets and objective assets, walks only validated evidence-backed relationships, prevents cycles, and enforces maximum-hop and maximum-path limits. A reported path must contain at least one finding on an asset in the path. Path prioritization uses already-computed finding risk supplied by the risk-analysis layer; the analyzer does not invent additional exploitability or compromise probability. The highest associated finding risk is used as the path's deterministic risk score, and an explicit risk level may be supplied from the risk engine.

This gate is intentionally network-free and persistence-independent. It creates the graph-analysis contract required for later evidence-backed attack-path persistence, remediation, and validation without allowing graph inference to bypass scope, evidence, or provider boundaries.

## 35. Architecture Gate 16

Gate 16 establishes the evidence management and validation lifecycle. Raw Evidence remains immutable and its SHA-256 digest is the content-integrity anchor established by the provider handoff. Validation decisions are separate domain records and never rewrite the evidence payload.

Evidence validation states are explicit: PENDING may transition to VALIDATED or REJECTED; final decisions may only become SUPERSEDED through an append-only replacement record. Validation records require a validator and rationale, and final decisions require supporting evidence references. Persistence rejects validation against missing evidence and re-checks the stored SHA-256 content digest before accepting a decision.

SQLite and PostgreSQL persist validation records behind the repository boundary with foreign keys to evidence and optional supersession links. This makes validation auditable across restarts and prevents a mutable status field from erasing prior decisions. The boundary does not claim that validation itself proves exploitability, remediation, or compromise; those conclusions require later evidence-backed workflows.


## 36. Architecture Gate 17

Gate 17 establishes the authentication and authorization boundary before higher-level assessment/remediation exposure. User credentials are represented by a dedicated User contract and password material is stored only as a PBKDF2-HMAC-SHA256 derived value with a per-user random salt. Successful authentication creates a short-lived opaque session token; only its SHA-256 hash is persisted. Sessions are revocable and expire fail-closed.

Role-based permissions are explicit: ADMIN has all permissions, ANALYST can READ/ASSESS/VALIDATE/REMEDIATE, and VIEWER can only READ. The assessment orchestration boundary requires an authenticated principal with ASSESS permission; campaign authorization remains a separate required safety control. Missing principals and insufficient permissions are rejected before provider execution.

Authentication, logout, authorization denials, and scan queue events are persisted as audit events. SQLite and PostgreSQL implement equivalent user/session/audit persistence. Raw passwords and raw session tokens are never persisted. This gate establishes backend security primitives without coupling the domain to a particular HTTP framework; HTTP/API authentication adapters can be layered later without weakening the core boundary.


## 37. Architecture Gate 18

Gate 18 hardens provider execution reliability without claiming capabilities Python threads cannot provide. ExecutionPolicy now defines a bounded cancellation-grace interval after a provider exceeds its execution timeout. The runtime sets the cooperative cancellation event, waits only for the configured grace interval, and explicitly records whether the provider worker is still running. A timed-out execution can never become successful.

Provider telemetry collection is protected by a lock because provider work and observers may execute concurrently. Event snapshots used for metrics and returned results are therefore consistent with the runtime's concurrent execution boundary. The runtime still uses daemon threads and cooperative cancellation; it does not falsely claim to forcibly terminate arbitrary provider code. A non-cooperative provider is surfaced as an explicit reliability condition for higher orchestration/operational handling.


## 38. Architecture Gate 18 Reliability Hardening — Lifecycle Compare-and-Set

The scan lifecycle persistence boundary now exposes atomic compare-and-set finalization and an atomic cancellation operation. Completion, failure, and partial outcomes require the persisted scan to still be RUNNING; cancellation may atomically transition only QUEUED or RUNNING executions. If cancellation wins a race, a late provider completion/failure cannot overwrite the terminal CANCELLED state.

SQLite implements these operations with conditional UPDATE statements inside repository transactions. PostgreSQL provides equivalent conditional UPDATE semantics. The orchestrator treats a failed compare-and-set as a storage-authoritative indication that another lifecycle transition already won and reloads the persisted state rather than forcing an invalid transition.

Cancellation of an already-terminal scan is idempotent at the lifecycle boundary and is recorded as a NOOP audit outcome. This prevents race-dependent lifecycle corruption and keeps persistence authoritative under concurrent control actions.


## 39. Architecture Gate 18 Reliability Hardening — Provider Concurrency and Transaction Boundaries

Provider execution concurrency is now enforced at the execution-runtime boundary from the authoritative ExecutionPolicy.max_concurrency value. ScanOrchestrator owns a shared bounded concurrency gate so parallel executions through the same orchestrator cannot exceed the configured provider-worker limit. The runtime does not release a slot merely because its orchestration timeout returned: the provider worker releases its slot only when the worker exits. This is required to prevent a non-cooperative timed-out worker from silently exceeding the configured concurrency ceiling.

Execution waiting is cancellation-aware. A queued runtime execution can observe a cancellation request before acquiring a provider slot and terminate without starting provider work. The concurrency control is therefore a safety boundary, not only a throughput optimization.

Persistence transaction boundaries are hardened alongside concurrency. SQLite lifecycle read/validate/write transitions execute inside one transaction and repository lifecycle access is serialized with a re-entrant lock; the SQLite connection permits controlled cross-thread lifecycle cancellation while maintaining serialized connection use. PostgreSQL now implements the same update_scan_state contract, locks the target lifecycle row during read/validate/write transitions, and serializes scan/audit transaction access. Pre-start cancellation uses the atomic cancellation primitive rather than a separate lifecycle transition path.

The persistence layer remains authoritative: provider completion, provider failure, and external cancellation still compete through atomic lifecycle operations. These changes do not broaden provider capabilities, scope, or assessment aggressiveness; they only constrain execution concurrency and strengthen persistence consistency under concurrent control paths.
\n## 40. Architecture Gate 18 Reliability Hardening — Persistence Failure Atomicity and Recovery

Lifecycle persistence is authoritative and must not be partially committed. Queue creation, lifecycle finalization, and cancellation therefore use repository-level transactions that couple the scan state mutation with the corresponding audit event. A failure in either side rolls back the complete transaction.

Provider execution errors and persistence errors are distinct failure classes. The orchestrator catches provider exceptions only around provider execution; lifecycle finalization persistence failures are not converted into provider failures. This prevents a successful provider execution from being falsely recorded as FAILED when the database cannot commit the final state.

After a persistence failure, the last committed lifecycle state remains authoritative. Recovery is deterministic: once the persistence fault is removed, the valid lifecycle transition may be retried against that durable state. No in-memory provider result is treated as persisted completion until the atomic lifecycle-plus-audit transaction commits.

SQLite and PostgreSQL expose equivalent atomic repository operations. Both use transaction rollback on any failure, while repository locks serialize access to the underlying connection where required.



## 41. Architecture Gate 18 Reliability Hardening — Execution Heartbeat and Stale Recovery

A durable RUNNING lifecycle requires evidence that the execution owner is still alive. Scan persistence therefore stores heartbeat_at, refreshed by the provider runtime at the configured heartbeat interval. ExecutionPolicy defines heartbeat_interval_seconds and stale_after_seconds, with the stale threshold required to exceed the heartbeat interval.

Stale recovery is explicit and authenticated. The repository may transition a scan from RUNNING to FAILED only when the heartbeat lease is expired, and the transition plus SCAN_RECOVERED_STALE audit event occur in one transaction. A recent heartbeat is never recovered. The design deliberately avoids age-only recovery because a legitimate long-running assessment may exceed arbitrary wall-clock durations.

SQLite and PostgreSQL expose equivalent heartbeat and stale-recovery operations. Recovery is fail-closed: persistence errors roll back the lifecycle mutation and audit event. Provider execution is never automatically rerun as part of stale recovery.


## 29. Architecture Gate 18 — Reliability and Performance

Gate 18 is complete after explicit local validation. The reliability boundary includes bounded cooperative cancellation grace, explicit reporting of non-cooperative workers, shared provider concurrency limits, cancellation-aware slot acquisition, compare-and-set lifecycle transitions, atomic lifecycle/audit persistence, recovery after persistence faults, durable execution heartbeats, explicit authenticated stale-lease recovery, and deterministic cleanup of heartbeat workers after provider timeout. The persistence layer remains authoritative for lifecycle state; Python threads are never represented as forcibly terminated.

## 30. Architecture Gate 19 — PostgreSQL Canonical Persistence Enforcement — COMPLETE

Gate 19 is complete after local validation. PostgreSQL is the sole active development and integration-test persistence path. The shared test fixture requires an explicit PostgreSQL DSN, never silently falls back to SQLite, and isolates test state deterministically. Existing persistence, authentication, correlation, evidence-validation, orchestration, concurrency, lifecycle-CAS, and failure-atomicity tests have been migrated to PostgreSQL. The legacy SQLite adapter is retained only for compatibility and is not selected by the application runtime or active test suite.

## 31. Architecture Gate 20 — PostgreSQL Transactional Concurrency and Failure-Recovery Hardening

Gate 19 makes the already-declared PostgreSQL production boundary singular across active development and integration testing. Active repository tests and fixtures must use PostgreSQL, configured through an explicit test database connection such as THREATLENS_TEST_DATABASE_URL; tests must not silently fall back to SQLite. SQLite code, if retained temporarily for legacy compatibility, must not receive new production behavior and must not be selected by the application runtime. The gate is complete only after PostgreSQL-backed tests validate domain persistence, lifecycle transactions, correlation persistence, evidence-validation persistence, authentication persistence, concurrency behavior, and failure-atomicity behavior without weakening constraints or safety controls.


## 42. Architecture Gate 20 — PostgreSQL Transactional Concurrency and Failure-Recovery Hardening — COMPLETE

Gate 20 closes the PostgreSQL concurrency hardening boundary. Durable finding correlation uses a transaction-scoped advisory lock and row-level locking so concurrent independent application instances cannot create duplicate logical findings for the same correlation key. Evidence-validation lifecycle transitions lock the current validation record before evaluating and writing a transition or supersession. Orchestration regression coverage exercises independent PostgreSQL connections racing stale recovery and cancellation against provider finalization; exactly one lifecycle winner is accepted and audit state remains consistent.

These controls rely on PostgreSQL transactional semantics rather than process-local Python locks for cross-instance correctness. Persistence failures remain fail-closed and do not permit an in-memory provider result to masquerade as a committed lifecycle state.

## 43. Architecture Gate 21 — Controlled Web Assessment Foundation — COMPLETE

Gate 21 establishes the first bounded HTTP assessment provider for explicitly authorized HTTP(S) URL targets. The provider accepts only absolute HTTP(S) URLs without userinfo or fragments, honors campaign exclusions and cancellation, bounds target count, request timeout, response size, and HTTP methods, and disables automatic redirect following. Redirect destinations are never treated as newly authorized scope.

The safe default method is HEAD. GET is available only when explicitly configured by the execution policy. The provider performs a destination safety check before network access and rejects destinations resolving to private, loopback, link-local, or reserved addresses unless the policy explicitly enables private-address assessment for an authorized environment. This is a conservative SSRF boundary, not a claim that DNS-based destination validation alone replaces campaign scope authorization.

Each HTTP response is serialized into immutable, SHA-256-sealed evidence with execution/provider provenance before any policy finding is generated. The current deterministic policy layer evaluates only evidence-backed response-header controls: missing HSTS on successful HTTPS responses and missing X-Content-Type-Options. Findings reference the exact persisted evidence and cross the ProviderHandoff boundary.

Gate 21 deliberately excludes authenticated API workflows, state-changing requests, parameter fuzzing, schema-driven API discovery, credential testing, SSRF exploitation, redirect traversal, and intrusive web testing. API-specific assessment will require a separate architecture gate with explicit authorization, execution, evidence, and safety contracts.


## 44. Architecture Gate 22 — Controlled API Assessment Foundation

Gate 22 establishes a separate bounded API assessment provider for explicitly authorized HTTP(S) API URL targets. The provider accepts only absolute HTTP(S) URLs without userinfo or fragments, honors campaign exclusions and cancellation, bounds target count, request timeout, response size, and HTTP methods, and disables automatic redirect following. The safe default method is HEAD; GET is available only when explicitly configured. Destination validation reuses the same conservative SSRF boundary as web assessment and rejects private, loopback, link-local, or reserved destinations unless private addressing is explicitly enabled for an authorized environment.

API responses are normalized into API-specific observations and persisted as immutable, SHA-256-sealed evidence through ProviderHandoff before any finding is generated. The initial deterministic API policy is intentionally narrow: a successful response explicitly labeled application/json may produce a LOW/SUSPECTED finding only when its captured body is malformed JSON and the capture is complete. Truncated captures, HEAD responses, non-JSON responses, and redirects do not create this finding because incomplete evidence must not be treated as malformed application output.

Gate 22 does not discover endpoints from response bodies, expand OpenAPI/Swagger schemas, follow API links, send credentials, test authentication bypasses, fuzz parameters, perform state-changing methods, exploit SSRF, or infer authorization weaknesses. API assessment remains explicitly scoped and evidence-first. Later authenticated/API-schema gates must introduce their own authorization, secret-handling, mutation, rate-limit, and evidence contracts rather than weakening this foundation.


## 45. Architecture Gate 22 — Controlled API Assessment Foundation — COMPLETE

Gate 22 establishes a bounded API assessment provider for explicitly authorized HTTP(S) API targets. It supports only bounded read-only HEAD/GET requests, disables redirects, applies destination safety validation, honors campaign exclusions and cancellation, persists complete observations as sealed evidence before policy evaluation, and produces only the conservative malformed-JSON policy finding defined by the gate. Authenticated workflows, schema expansion, parameter fuzzing, mutation, SSRF exploitation, and authorization-bypass testing remain outside the foundation.

## 46. Architecture Gate 23 — Vulnerability Intelligence Foundation — COMPLETE

Gate 23 establishes a trusted, provider-independent vulnerability-intelligence normalization boundary. `VulnerabilityIntelligenceRecord` represents explicitly supplied vulnerability metadata including normalized vulnerability identity, severity, optional CVE/CWE, affected product/version metadata, optional fixed version, CVSS, confidence, references, source provenance, and optional evidence references.

The normalization function is network-free and fail-closed. CVE and CWE identifiers are syntax-validated, confidence and CVSS are range-validated, blank metadata is rejected, and source/evidence provenance is preserved. The platform does not fetch external feeds in this gate, infer identifiers from service banners, or transform intelligence metadata into vulnerability findings by itself.

## 47. Architecture Gate 24 — Deterministic Vulnerability Matching — COMPLETE

Gate 24 establishes a conservative matching layer between normalized service observations and trusted vulnerability intelligence. A vulnerability match requires all of the following: the service belongs to the explicitly supplied authorized asset, the intelligence record identifies a product, the service has an explicit service name and version, the product and service name agree case-insensitively, and the observed version exactly matches an affected version supplied by trusted intelligence.

The matcher returns a bounded `VulnerabilityMatch` containing vulnerability identity, asset/service identity, deterministic rationale, intelligence confidence, and intelligence source. It returns no match for missing metadata, different assets, different products, or non-exact versions. It does not infer exploitability, create findings, or bypass ProviderHandoff/evidence requirements. Any future intelligence-backed finding enrichment must preserve the existing evidence-first handoff and correlation contracts.


## Validation Status

Gate 22 has been locally validated clean. Gates 23–24 have also been locally validated clean with `pytest -q` and `ruff check .`. Gate 25 remains pending local validation. Gate 26 is now complete after local validation. Gate 27 is complete after explicit local validation. Gate 28 is complete after explicit local validation. Gate 29 is complete after explicit local validation.


## 48. Architecture Gate 25 — Evidence-Backed Vulnerability Finding Enrichment — IMPLEMENTED

Gate 25 establishes the controlled bridge from trusted vulnerability intelligence to an existing normalized finding. Enrichment requires an explicit deterministic VulnerabilityMatch and the intelligence record must reference evidence supplied in the same ProviderHandoff input. The enrichment result preserves the finding's existing evidence, unions trusted intelligence evidence, applies normalized vulnerability identity, CVE/CWE, CVSS, confidence, severity, and source provenance, and then routes the enriched finding through the existing ProviderHandoff and optional durable correlator.

The boundary is network-free and fail-closed. It does not fetch feeds, infer affected versions, invent CVEs, assert exploitability, or bypass asset/evidence validation. Intelligence metadata is treated as supporting evidence for an existing finding, not as an independent vulnerability claim.

Validation remains pending local execution of pytest -q and ruff check .; Gate 25 must not be declared complete until those checks succeed.


## 49. Architecture Gate 26 — Vulnerability Correlation Context Expansion — IMPLEMENTED

Gate 26 expands deterministic finding identity beyond asset and vulnerability identity. The normalized Finding contract now supports explicit service_id, endpoint, parameter, and location context. These values are observational context supplied by an assessment provider; they are never inferred by the correlation engine.

The correlation key includes every context dimension. UUID service identity is represented deterministically, while textual endpoint, parameter, and location values are case-folded and whitespace-normalized. A missing context value is distinct from a supplied value, so a context-bearing finding cannot silently correlate with a context-free finding. Findings on different services, endpoints, parameters, or locations therefore remain separate logical findings even when they share the same asset and vulnerability identity.

PostgreSQL persists the expanded context with a foreign key from findings.service_id to services.id, plus endpoint/parameter/location fields. Existing installations receive additive columns during initialization. The legacy SQLite adapter receives the same additive compatibility migration, while PostgreSQL remains the canonical production persistence path. Durable correlation reloads and updates the same context fields used by in-memory correlation, preventing divergence between transient and persisted identities.

Gate 26 does not introduce endpoint discovery, parameter fuzzing, exploitation, or automatic context inference. It only strengthens identity for evidence-backed findings already produced by authorized providers.

Gate 26 is complete after explicit local validation.


## 50. Architecture Gate 27 — Risk Context Provenance — IMPLEMENTED

Gate 27 strengthens the explainable risk boundary by requiring explicit provenance whenever environmental risk context is supplied. RiskContext now accepts a source identifier and rejects supplied context with no declared source. RiskAssessment retains the context source so downstream API, GUI, and reporting layers can show where environmental risk inputs originated.

This does not fabricate environmental telemetry or infer business impact, exposure, criticality, threat relevance, exploitability, or control coverage. Unknown values remain unknown and are excluded from the weighted calculation as before. Operator-supplied context remains supported when its source is explicitly identified.

Gate 27 is complete after explicit local validation.


## 51. Architecture Gate 28 — Application API Boundary Foundation — IMPLEMENTED

Gate 28 establishes the HTTP control-plane boundary between the ThreatLens domain/application layers and the future graphical interface. The FastAPI application exposes a public health check and versioned authentication endpoints for login, logout, and the authenticated current principal. Bearer session tokens are validated exclusively through AuthenticationService; raw tokens are not persisted, and authorization decisions continue through the existing role/permission model.

The API factory accepts injected repository and authentication services, keeping transport concerns separate from persistence and domain contracts and making the boundary testable without weakening production PostgreSQL requirements. The production entrypoint connects to the canonical PostgreSQL repository using THREATLENS_DATABASE_URL and performs read-only schema/audit readiness verification. Schema DDL is applied only by the explicit `python -m threatlens.storage.migrate` command using THREATLENS_MIGRATION_DATABASE_URL.

The initial API surface deliberately does not expose arbitrary database access or assessment mutation. Campaign execution, findings, evidence, risk, attack paths, and reporting endpoints will be added behind explicit application contracts so the GUI cannot bypass authorization, scope, evidence, or orchestration boundaries.

Gate 28 is complete after explicit local validation.


## 52. Architecture Gate 29 — Dashboard Read Model API — COMPLETE

Gate 29 establishes the first GUI-facing application read model. The authenticated `GET /api/v1/dashboard/summary` endpoint exposes bounded aggregate counts for campaigns, assets, services, findings, finding severity, and scan lifecycle state. It requires the existing READ permission and returns an application-level response model rather than database rows or arbitrary query parameters.

The PostgreSQL repository supplies the aggregate data through fixed queries. The boundary is read-only and intentionally excludes detailed evidence, finding contents, credentials, audit records, or unrestricted database access. Future GUI detail views will receive separate least-privilege contracts.

Gate 29 is complete after explicit local validation.


## 53. Architecture Gate 30 — Findings Read Model API — COMPLETE

Gate 30 establishes the authenticated application read model for finding inventory. `GET /api/v1/findings` requires READ permission and returns a bounded page containing finding identity, lifecycle state, severity, vulnerability metadata, confidence, source, detection time, asset canonical identity, and explicit service/endpoint/parameter/location context.

The repository contract is deliberately read-only and bounded. PostgreSQL uses fixed SQL with deterministic ordering and a maximum page size of 100. The response never exposes raw evidence content, evidence metadata, audit records, or arbitrary query/database controls. Evidence detail and future remediation/validation workflows require separate least-privilege application contracts.

The API therefore gives the future GUI a usable findings table without allowing the presentation layer to bypass the domain, authorization, evidence, or persistence boundaries.

Gate 30 is complete after explicit local validation.


## 56. Architecture Gate 33 — Campaign & Scope Read Model API — COMPLETE

Gate 33 establishes the authenticated application read model for campaign authorization boundaries. The `GET /api/v1/campaigns` endpoint requires READ permission and returns bounded campaign identity, explicit authorization state, lifecycle state, creation time, and persisted include/exclude scope entries.

The PostgreSQL repository uses fixed SQL with a maximum page size of 100 and deterministic ordering. Scope is exposed exactly as persisted authorization data; the read model does not infer new targets, expand network ranges, follow discovered assets, or turn observed destinations into authorized scope.

The endpoint is strictly read-only. Campaign creation, scope mutation, authorization changes, and assessment execution remain separate control-plane operations requiring their own authenticated permissions, audit semantics, and fail-closed validation.

Gate 33 is complete after explicit local validation.

## 57. Architecture Gate 34 — Authenticated Scan Lifecycle Control API — COMPLETE

Gate 34 exposes the existing `ScanOrchestrator` lifecycle controls through the authenticated HTTP application boundary. `POST /api/v1/scans/{execution_id}/cancel` and `POST /api/v1/scans/{execution_id}/recover-stale` require `ASSESS` permission and pass the authenticated principal directly to the orchestrator. FastAPI does not reproduce lifecycle state transitions or audit writes.

Cancellation remains governed by the existing transactional lifecycle contract: only queued/running executions can change to `CANCELLED`, terminal cancellation is audited as a no-op, and cross-instance races remain resolved by PostgreSQL persistence semantics. Stale recovery remains governed by the durable heartbeat lease and only transitions an eligible stale running execution to `FAILED` with its recovery audit event.

The API returns the persisted lifecycle state after the control operation, distinguishes a state-changing recovery from a no-op, returns 404 for unknown executions, and rejects malformed execution identifiers. These endpoints do not invoke providers, expand scope, or create new authorization paths.

Gate 34 is complete after explicit local validation.

## 55. Architecture Gate 32 — Scan Read Model API — IMPLEMENTED

Gate 32 establishes the authenticated application read model for scan execution state. The `GET /api/v1/scans` endpoint requires READ permission and returns bounded execution metadata: execution and campaign identity, campaign name, provider name, lifecycle state, queued/started/finished timestamps, heartbeat timestamp, and a bounded error summary.

PostgreSQL uses fixed SQL with a maximum page size of 100 and deterministic ordering. The repository contract is read-only. The response excludes raw evidence, credentials, audit records, arbitrary SQL controls, and provider-internal execution details. It exposes operational state without allowing the GUI to mutate scan lifecycle state or bypass the orchestration boundary.

The endpoint is intentionally a read model rather than a control API. Cancellation, recovery, campaign mutation, and assessment execution require separate authenticated application contracts with their own authorization and audit semantics.

Gate 32 is complete after explicit local validation.

## 54. Architecture Gate 31 — Asset & Service Read Model API — IMPLEMENTED

Gate 31 establishes the authenticated application read model for the authorized attack-surface inventory. `GET /api/v1/assets` requires READ permission and returns bounded asset identity plus explicit service observations associated with each asset.

The response includes canonical asset identity, asset type/value, first/last observation timestamps, and service protocol/port/name/version. PostgreSQL uses fixed queries with a maximum page size of 100 and deterministic ordering. The endpoint is read-only and excludes raw evidence, credentials, audit records, arbitrary SQL, and unrestricted database access.

The service information remains observational context. The read model does not infer vulnerabilities or exploitability and does not bypass the existing provider, evidence, correlation, or authorization boundaries.

Gate 31 is complete after explicit local validation.


## 58. Architecture Gate 35 — Authenticated Evidence Read Model API — COMPLETE

Gate 35 establishes the authenticated application read boundary for immutable evidence metadata. `GET /api/v1/evidence` requires the existing READ permission and returns a bounded, paginated application model containing evidence identity, kind, source, capture time, SHA-256 integrity identity, and provider/execution metadata.

The API deliberately does not expose raw evidence content. Evidence remains immutable and its SHA-256 digest remains the integrity anchor established by ProviderHandoff. This gate is read-only and does not create an evidence mutation, validation-transition, arbitrary SQL, or provider-execution path.

PostgreSQL supplies the evidence read model through fixed SQL with a maximum page size of 100 and deterministic ordering by capture time and evidence identity. The application boundary does not reconstruct findings, infer trust, or treat evidence metadata as a vulnerability claim.

Authentication and authorization remain delegated to AuthenticationService and the existing READ permission boundary. Evidence validation lifecycle mutation remains outside this gate and continues to use the existing append-only persistence contracts.

Gate 35 is complete after explicit local validation.


## 59. Architecture Gate 36 — Authenticated Evidence Validation Lifecycle API — COMPLETE

Gate 36 exposes the existing evidence-validation lifecycle through an authenticated application boundary without duplicating or bypassing the domain/persistence contracts. Validation creation is available at `POST /api/v1/evidence/{evidence_id}/validations`, while lifecycle transitions are available at `POST /api/v1/evidence/validations/{validation_id}/transition`. Both require the existing VALIDATE permission.

The authenticated principal supplies the validator identity and audit actor identity. The client cannot choose an arbitrary validator username. Rationale is required and bounded, final decisions continue to require supporting evidence through the immutable `EvidenceValidation` domain contract, and SUPERSEDED is only reachable through an existing validation transition.

The application service delegates all integrity checks and lifecycle enforcement to `EvidenceValidationPersistence`. PostgreSQL re-verifies the target evidence SHA-256 digest, verifies supporting evidence references, locks the current validation row with `FOR UPDATE`, enforces the existing allowed state transitions, preserves evidence identity, and appends the new immutable validation record. The validation mutation and its security audit event are committed in the same PostgreSQL transaction, so audit persistence failure rolls back the lifecycle mutation.

The API exposes no raw evidence content mutation, provider execution, arbitrary SQL, client-controlled validator identity, or alternate validation state machine. Concurrency remains governed by the existing PostgreSQL row-locking boundary.

Gate 36 is complete after explicit local validation.


## 60. Architecture Gate 37 — Authenticated Scan Queue Control API — COMPLETE

Gate 37 exposes the existing scan queueing application boundary through `POST /api/v1/campaigns/{campaign_id}/scans`. The endpoint requires the existing ASSESS permission, loads the authorized campaign from PostgreSQL, resolves the requested provider only through the injected `ProviderRegistry`, and delegates scan creation to `ScanOrchestrator.queue()`.

The API returns only the newly persisted QUEUED execution identity, campaign identity, provider name, and lifecycle state. It does not execute the provider, mutate campaign scope, infer authorization, or accept arbitrary provider implementations. The authenticated principal is passed directly into the orchestrator, which remains responsible for campaign execution-policy validation and the atomic `SCAN_QUEUED` audit event.

PostgreSQL adds a bounded `campaign_by_id()` repository lookup that reconstructs the persisted campaign and explicit include/exclude scope before orchestration. Missing campaigns and unregistered providers fail closed. Provider execution remains outside this HTTP queue-control gate.

Focused API regression coverage verifies authentication, ASSESS authorization, principal propagation, campaign/provider lookup failures, malformed campaign identifiers, queued-state response, audit creation, and the absence of provider execution.

Gate 37 is complete after explicit local validation.


## 61. Architecture Gate 38 — Authenticated Campaign & Scope Control API — IMPLEMENTED

Gate 38 establishes the authenticated campaign authorization control boundary at `POST /api/v1/campaigns`. Only principals with ADMIN permission may create an authorized campaign. The request requires explicit authorization acknowledgement and bounded include/exclude scope arrays; the immutable Campaign and Scope domain contracts remain authoritative for validation.

PostgreSQL adds `save_campaign_with_audit()`, which persists the campaign, scope container, and all scope entries together with the `CAMPAIGN_CREATED` audit event in one transaction. Any persistence failure rolls back the complete campaign creation mutation. The audit actor is always the authenticated principal and is not client-controlled.

The endpoint does not execute scans, expand scope, infer authorization, or grant assessment permission. Analysts and viewers cannot create authorized campaigns through this control boundary.

Focused regression tests cover authentication, ADMIN authorization, explicit authorization acknowledgement, exact scope persistence/response, audit actor binding, and empty-scope rejection.

Gate 38 is complete after explicit local PostgreSQL-backed `pytest -q` and `ruff check .` validation.


## 62. Architecture Gate 39 — Authenticated Finding Remediation Control API — IMPLEMENTED

Gate 39 establishes the authenticated remediation control boundary for existing normalized findings. The endpoint `POST /api/v1/findings/{finding_id}/remediation` requires the existing REMEDIATE permission and accepts only the remediation outcomes MITIGATED and ACCEPTED_RISK with a bounded operator rationale.

The finding domain now exposes an explicit fail-closed remediation transition contract. Only a CONFIRMED finding may transition into MITIGATED or ACCEPTED_RISK. Validation-oriented finding decisions such as CONFIRMED, FALSE_POSITIVE, NOT_REPRODUCIBLE, and INFORMATIONAL are intentionally outside this remediation control.

PostgreSQL applies the remediation transition inside one transaction. The target finding row is locked with `FOR UPDATE`, the domain transition contract is evaluated against the locked state, the successful state update uses a compare-and-set predicate, and the security audit event is written in the same transaction. A denied transition is also audited without mutating the finding. Repeating an already-applied terminal remediation state is an audited no-op.

The authenticated principal is the sole audit actor. The API does not mutate evidence, create findings, execute providers, alter campaign scope, or introduce a second finding state machine.

API regression tests cover authentication, REMEDIATE authorization, successful remediation, denied invalid transitions, idempotent terminal-state requests, missing findings, and audit actor binding. Domain tests cover the fail-closed transition matrix, while PostgreSQL integration tests cover durable mutation and atomic audit behavior.

Gate 39 is complete after explicit local PostgreSQL-backed `pytest -q` and `ruff check .` validation.

  
## 63. Architecture Gate 40 — Authenticated Finding Risk Assessment API — IMPLEMENTED

Gate 40 establishes the authenticated risk-assessment control boundary for an existing normalized finding. The endpoint `POST /api/v1/findings/{finding_id}/risk-assessments` requires ASSESS permission and delegates calculation to the existing deterministic `RiskEngine`.

The HTTP contract accepts only explicitly normalized environmental inputs in the range 0..1. Whenever environmental context is supplied, a bounded source identifier is required. Missing values remain unknown and are excluded from the weighted calculation, preserving the existing explainability contract rather than treating absent telemetry as zero risk.

The PostgreSQL repository reconstructs the normalized finding from canonical persistence, persists a unique risk-assessment record containing the full context, deterministic factors, explanations, inputs used, missing inputs, and context provenance, and commits the assessment together with a `RISK_ASSESSMENT_CREATED` security audit event. The authenticated principal is always the audit actor.

The API returns the durable assessment identity and deterministic risk decision without exposing raw evidence or introducing arbitrary query controls. It does not create findings, mutate evidence, execute providers, modify campaign scope, or implement an alternate risk algorithm.

Regression coverage includes authentication, ASSESS authorization, required context provenance, deterministic risk output, unknown-finding handling, domain risk semantics, and PostgreSQL persistence/audit behavior.

**Validation status:** Gate 40 implementation and regression tests are committed. Local PostgreSQL-backed `pytest -q` and `ruff check .` are required before Gate 40 can be declared complete.


## 64. Architecture Gate 41 — Authenticated Risk Assessment Read Model API — IMPLEMENTED

Gate 41 exposes persisted risk assessments through the authenticated application read boundary at `GET /api/v1/findings/{finding_id}/risk-assessments`. The endpoint requires READ permission and first verifies that the finding exists in canonical PostgreSQL persistence.

The response is bounded to a maximum page size of 100 and uses deterministic `created_at DESC, id DESC` ordering. It exposes the durable assessment identity, finding identity, risk level and score, explicitly persisted environmental context, factor scores/weights/contributions, explanations, inputs used, missing inputs, context provenance, and creation time.

The read path is strictly read-only. It does not expose raw evidence, audit records, arbitrary SQL controls, provider execution, campaign mutation, or a second risk-scoring implementation. Factor contributions are reconstructed from the persisted deterministic factor score and weight, so the read model remains faithful to the assessment already committed by Gate 40.

Focused regression coverage verifies authentication, READ authorization, bounded pagination, deterministic assessment fields, and missing-finding handling.

**Validation status:** Gate 41 implementation and regression tests are committed. Local PostgreSQL-backed `pytest -q` and `ruff check .` are required before Gate 41 can be declared complete.


## 65. Architecture Gate 42 — Durable Attack-Path Relationship Validation Boundary — IMPLEMENTED

Gate 42 establishes the PostgreSQL persistence boundary for explicit attack-path relationships. Relationships are stored separately from findings and require source/target assets plus at least one sealed evidence reference. Newly persisted relationships always begin unvalidated; the persistence layer does not accept client-controlled validation state.

Relationship validation is a separate transactional operation. PostgreSQL locks the relationship row, re-verifies every referenced evidence digest, and requires every referenced evidence item to have a current VALIDATED evidence decision. Only then is the relationship marked validated with the authenticated validator identity and validation timestamp. Re-validating an already validated relationship is an audited no-op.

The mutation and security audit event are committed atomically. The boundary does not infer network reachability, trust, application flow, or authenticated access from asset data, and it does not expose an alternate attack-path algorithm. The existing deterministic AttackPathAnalyzer remains the sole path-analysis engine.

Focused PostgreSQL regression coverage verifies unvalidated creation, asset/evidence integrity, validation fail-closed behavior, audit binding, and idempotent validation.

**Validation status:** Gate 42 implementation and regression tests are committed. Local PostgreSQL-backed `pytest -q` and `ruff check .` are required before Gate 42 can be declared complete.


## 68. Architecture Gate 45 — Authenticated Attack-Path Analysis API — COMPLETE

Gate 45 exposes the existing deterministic `AttackPathAnalyzer` through `POST /api/v1/attack-path/analyze`, requiring ASSESS permission. Callers must provide explicit entry and objective asset IDs. Duplicate IDs and overlapping entry/objective sets are rejected. The repository verifies requested assets exist and loads persisted relationship edges, evidence-backed findings, and the latest persisted risk assessment per finding. Graph inputs are bounded to 5,000 relationships and 10,000 findings; API controls bound entry/objective sets, hops, and returned paths. The analyzer remains deterministic and only follows validated, evidence-backed relationships. Successful analysis is audited with the authenticated principal. The API does not create findings, infer missing relationships, execute providers, or persist synthetic evidence.

**Validation status:** User confirmed local `python -m pytest -q` and `ruff check .` passed. Gate 45 is complete.

## 67. Architecture Gate 44 — Authenticated Attack-Path Relationship Read Model API — COMPLETE

Gate 44 adds `GET /api/v1/attack-path/relations`, protected by READ permission. The endpoint uses bounded pagination (limit 1–100) and deterministic ordering by creation timestamp and ID descending. It returns explicit relationship metadata, validation actor/time, and evidence identifiers, but never raw evidence content. PostgreSQL is the authoritative read source. The API does not infer graph edges or run attack-path analysis.

**Validation status:** User confirmed local `pytest -q` and `ruff check .` passed. Gate 44 is complete.

## 66. Architecture Gate 43 — Authenticated Attack-Path Relationship Control API — COMPLETE

Gate 43 exposes explicit attack-path relationship creation and validation through the authenticated API. `POST /api/v1/attack-path/relations` requires ASSESS permission and accepts only a source asset, target asset, enumerated relationship type, and bounded evidence references. The persistence boundary verifies both assets and sealed evidence integrity and always stores the relation as unvalidated.

`POST /api/v1/attack-path/relations/{relation_id}/validate` requires VALIDATE permission. PostgreSQL remains authoritative for row locking, evidence digest verification, current evidence-validation decisions, and atomic security audit persistence. The response is reconstructed from the durable relationship record; client input cannot set validation state or validator identity.

The API does not infer connectivity, trust, or exploitability and does not execute attack-path analysis. The deterministic analyzer continues to consume only explicitly validated, evidence-backed relations.

Focused API regression tests cover permission boundaries, explicit relationship typing, self-edge rejection, unvalidated creation, principal binding, and missing relationships.

**Validation status:** User confirmed local `pytest -q` and `ruff check .` passed. Gate 43 is complete.


## 69. Architecture Gate 46 — First Authenticated Dashboard UI Vertical Slice — COMPLETE

Gate 46 introduces the first visible web interface without replacing or bypassing the existing application and authorization boundaries. FastAPI serves the dashboard document at `/` and packaged static assets at `/ui/assets`. The responsive dashboard provides a sign-in screen and read-only panels for persisted campaign, asset, service, finding, severity, and scan lifecycle data by calling the existing READ-protected endpoints for dashboard summary, assets, findings, scans, and the authenticated principal.

The page does not create scans, findings, relationships, or evidence. Session tokens are held in tab-scoped `sessionStorage`, supplied only through the Authorization header, and cleared on sign-out or a rejected session. API values are rendered as text rather than interpolated into HTML. The dashboard document sends a restrictive same-origin Content Security Policy, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: same-origin`. Python package-data configuration includes the HTML, JavaScript, and CSS assets for installed deployments.

A focused regression test checks the dashboard response, security headers, and static asset delivery.

**Validation status:** User confirmed local `python -m pytest -q`, `ruff check .`, and package wheel build passed. Gate 46 is complete.


## 70. Architecture Gate 47 — Durable Login Abuse Protection — COMPLETE

Gate 47 protects the login boundary before password verification. The API uses the direct transport peer address and normalized username to derive SHA-256 pseudonymous bucket fingerprints without persisting raw identifiers; these hashes are not treated as anonymization. It deliberately ignores `X-Forwarded-For` and related client-controlled forwarding headers unless a separate trusted-proxy boundary is explicitly designed. PostgreSQL stores only the bucket fingerprint, window start, and attempt count. Atomic upserts provide cross-instance serialization, with a five-attempt per username/direct-peer limit and a 30-attempt per direct-peer limit over a 60-second window anchored to the first attempt. Old buckets are pruned, and blocked requests receive HTTP 429 plus a Retry-After header. A `LOGIN_RATE_LIMITED` audit event is written only at the threshold crossing to avoid unbounded audit amplification.

Password verification now validates the PBKDF2 encoding before derivation: iteration counts must be within 100,000–1,000,000, salt length must be 16 bytes, and digest length must be 32 bytes. This retains compatibility with the current 600,000-iteration hashes while preventing malformed stored values from selecting unbounded derivation cost.

The boundary fails closed if durable rate-limit persistence fails; it does not silently fall back to per-process counters. Regression coverage checks rate-limit behavior before valid-password verification, ignored forwarded headers, bounded password-hash parameters, durable PostgreSQL counters, and window expiry.

**Validation status:** Gate 47 is complete after the user confirmed local PostgreSQL-backed tests, Ruff, and package build checks passed.


## 71. Architecture Gate 48 — Authenticated Security Audit Read Model API — COMPLETE

Gate 48 exposes the existing PostgreSQL audit history through the read-only `GET /api/v1/audit-events` endpoint guarded by the existing `Permission.ADMIN` authorization boundary. It reuses the existing audit persistence and authentication system and introduces no second audit engine, mutation endpoint, or alternate persistence path.

The read model enforces bounded pagination (`limit=1..100`, `offset>=0`), parameterized fixed SQL, and deterministic `created_at DESC, id DESC` ordering. Its explicit allowlist returns event identifiers, actor/resource identifiers, action, resource type, outcome, and timestamp while excluding free-text `detail`, password hashes, session-token hashes, credentials, and secret material. Returned text fields are bounded, and an index supports the ordering.

API tests cover authentication, ADMIN authorization, pagination bounds, empty pages, response-field allowlisting, and secret-disclosure regression. PostgreSQL integration tests cover empty results, deterministic ordering, pagination, and omission of free-text details.

**Validation status:** User confirmed 33 focused API/PostgreSQL integration tests passed, the full pytest suite passed, `ruff check .` passed, `git diff --check` passed, and `python -m pip wheel . --no-deps --wheel-dir /tmp/apm-threatlens-wheel` built the package successfully. Five existing Starlette deprecation warnings were reported during the full suite; they did not fail validation.

## 72. Architecture Gate 49 — Durable Cross-Instance Scan Command Idempotency — COMPLETE

The authenticated scan-queue control endpoint requires an `Idempotency-Key` header with a bounded safe-ASCII format. The existing orchestration boundary computes a deterministic request fingerprint from campaign identity and registered provider identity, then delegates persistence to PostgreSQL. The repository serializes identical actor/key requests across application instances with a transaction-scoped advisory lock and atomically stores the scan, its `SCAN_QUEUED` audit event, and the idempotency mapping. Replaying the same key and request returns the original scan without creating another scan or audit event; reusing the key for a different request is rejected with HTTP 409. The response includes `Idempotency-Replayed` to distinguish a newly created execution from a replay.

Regression coverage includes missing/malformed keys, authentication and permission boundaries, replay stability, conflicting key reuse, atomic audit persistence, and concurrent requests through separate PostgreSQL connections. The user confirmed focused PostgreSQL/API tests, the full test suite, Ruff, diff checks, and package wheel build passed. The change was merged and verified on `main` at commit `e3a662eb93245160c5f11a01a9ff8b713bc24f0a`.

## 73. Architecture Gate 50 — Cross-Instance Scan Command Retry/Recovery Serialization — COMPLETE

Code inspection confirmed that cancellation and stale-recovery endpoints did not accept durable idempotency keys, so retries could create repeated lifecycle audit events even though PostgreSQL compare-and-set transitions protected scan state. Gate 50 adds an actor/key-bound PostgreSQL command record for CANCEL and RECOVER_STALE. The repository serializes matching keys with a transaction-scoped advisory lock, locks the scan row, applies the existing lifecycle rules, atomically persists any lifecycle audit event and command result, returns the original changed/not-changed result on exact retries, and rejects conflicting key reuse with HTTP 409. The authenticated API requires a bounded safe-ASCII Idempotency-Key and reports Idempotency-Replayed.

Regression tests cover API replay, missing/malformed keys, conflicting command reuse, and PostgreSQL concurrency through separate connections. Existing provider completion and lifecycle compare-and-set behavior remains unchanged; commands do not rerun providers. Validation status: The user confirmed all checks succeeded, including Ruff after the E501 fix. Gate 50 is COMPLETE based on that confirmation. The command record, lifecycle mutation, and any audit event are transactionally coupled; same-key retries return the original result, and conflicting key reuse fails closed. Next cycle must re-fetch latest main and deeply inspect the repository to identify the next highest-priority unfinished architecture gap before defining Gate 51.

## 74. Architecture Gate 51 — Fail-Closed Scan Heartbeat Lease Integrity — COMPLETE

The provider runtime previously treated heartbeat exceptions as warnings, ignored an explicit false return from the repository, and could continue executing after losing its durable RUNNING lease. This allowed a scan to remain active while another instance could legitimately recover its expired lease and mark it FAILED. The successful provider path also did not reliably stop the heartbeat worker, allowing heartbeat updates to continue after terminal finalization.

Gate 51 changes the runtime to treat heartbeat renewal exceptions and an explicit lease-loss result as a hard execution failure. It sets the cooperative cancellation event, emits structured error telemetry, returns a failed execution result rather than misclassifying lease loss as user cancellation, and gives the provider the configured cancellation grace period. The orchestrator then uses the existing compare-and-set finalization boundary, so a concurrent terminal transition remains authoritative. The direct orchestration path applies the same fail-closed behavior for initial and periodic heartbeat failures. Heartbeat workers are stopped after execution completes.

Focused runtime and PostgreSQL-backed orchestration regression tests cover explicit lease loss, storage exceptions, failed lifecycle finalization, and heartbeat-worker shutdown after successful completion.

**Validation status:** The user confirmed Gate 51 clean and successful, including the package wheel build. Gate 51 is COMPLETE based on that explicit confirmation.

## 75. Architecture Gate 52 — Execution-Lease-Fenced Evidence and Finding Persistence — COMPLETE

PostgreSQL execution-bound evidence and finding writes lock the authoritative scan row, require the execution to remain RUNNING, and persist under the same transaction. The production repository declares execution fencing mandatory. ProviderHandoff and DurableFindingCorrelator fail closed when fenced methods are unavailable, and generic PostgreSQL evidence writes reject execution-bound evidence.

**Validation status:** On 2026-10-14, the user confirmed the full suite reached 100% with no skip summary, the PostgreSQL-backed regression tests executed, Ruff passed, diff checks were clean, and the package wheel built successfully. Five Starlette deprecation warnings were non-failing.

## 76. Architecture Gate 53 — Durable Finding Remediation Idempotency — COMPLETE

The authenticated finding-remediation API requires a bounded `Idempotency-Key`. PostgreSQL stores the actor/key-scoped request fingerprint and original transition result in the same transaction as the finding state change and audit event. A transaction-scoped advisory lock serializes retries across application instances. Exact retries replay the original result without adding another audit event; conflicting key reuse returns HTTP 409. Invalid transitions are durably replayed with their original denied result and audit event.

**Validation status:** On 2026-10-14, 9 focused API tests and 5 focused PostgreSQL remediation tests passed; the full suite, Ruff, diff checks, and package wheel build also passed.

## 77. Architecture Gate 54 — Versioned PostgreSQL Schema Migrations — COMPLETE

`PostgresRepository.initialize()` delegates to a dedicated migration runner. The runner maintains `threatlens_schema_migrations` with ordered version, migration name, checksum, and applied timestamp. A stable session-level PostgreSQL advisory lock serializes startup across application instances. Version 1 adopts the existing idempotent initializer for pre-versioned installations; it is non-transactional because legacy helpers commit internally, so it must remain retry-safe. New migrations are append-only and transactional where supported, with the migration record committed atomically. Startup fails closed on unknown future versions, version gaps, or applied identity/checksum mismatch. The registry identifier is validated before SQL interpolation and values are parameterized. Existing data is preserved.

**Validation status:** On 2026-10-14, the user confirmed the focused migration tests (3 passed), focused remediation tests (14 passed), full PostgreSQL-backed suite (100%, no skip summary), Ruff, diff checks, and wheel build all succeeded on `f0f4d543947f864ff05d6e7173839b105562cd2c`. Five Starlette deprecation warnings were non-failing.

## 78. Architecture Gate 55 — Database-Enforced Append-Only Security Audit Trail — COMPLETE

Security audit events are protected by a transactional PostgreSQL migration that installs a row-level trigger rejecting UPDATE and DELETE operations on `audit_events`, while allowing normal inserts and preserving existing audit rows.

**Validation status:** On 2026-10-14, the user confirmed 4 focused schema-migration tests, 14 focused remediation API/PostgreSQL tests, the full PostgreSQL-backed suite with no skip summary, Ruff, diff checks, and package wheel build all passed on `8dcb6974132713bf426b30bfc202260c9a5ff699`. Five Starlette deprecation warnings were non-failing.

## 79. Architecture Gate 56 — PostgreSQL Audit Trail Truncation Protection — COMPLETE

A versioned statement-level `BEFORE TRUNCATE` trigger blocks ordinary truncation of `audit_events`, complementing the row-level UPDATE/DELETE guard. A TRUNCATE attempt is expected to fail with SQLSTATE `55000` while preserving existing rows after rollback. This does not protect against privileged database owners or superusers who can disable triggers or alter the schema.

**Validation status:** On 2026-10-14, the user confirmed 4 focused migration tests, 14 focused remediation tests, the full PostgreSQL-backed suite at 100% without a skip summary, Ruff, diff checks, and wheel build on `4e96495a5ee85e23b35033f364f379120898d159`. Five Starlette deprecation warnings were non-failing.

## 80. Architecture Gate 57 — Fail-Closed Audit Protection Drift Detection — COMPLETE

Migration history does not prove that audit-protection triggers remain installed and enabled after deployment. Startup checks PostgreSQL trigger-type bits, enabled state, event and row/statement semantics, expected function identity, and the normalized function body. It fails closed if either required trigger is missing, disabled, structurally altered, or no longer invokes the expected unconditional `RAISE EXCEPTION` implementation. Marker-string presence alone is not accepted as proof of behavior. Startup does not repair drift automatically; an operator must restore the schema and retry startup.

**Validation status:** On 2026-10-14, the user confirmed 8 focused PostgreSQL schema migration tests, the full PostgreSQL-backed suite without a skip summary, Ruff, diff checks, and wheel build passed on `db3b98165bb10351cb3fc2b10de964c44a5dcd90`. Five Starlette deprecation warnings were non-blocking.

## 81. Architecture Gate 58 — PostgreSQL Runtime/Migration Privilege Separation — COMPLETE

The API runtime no longer calls `PostgresRepository.initialize()`. It uses `verify_schema_ready()`, which checks exact migration registry history and audit trigger/function invariants with read-only catalog queries, fails closed on missing/drifted schema, and leaves the connection idle. The explicit `python -m threatlens.storage.migrate` command reads only `THREATLENS_MIGRATION_DATABASE_URL` and is intended to run as a controlled deployment step, outside the API process.

Deployment guidance separates the runtime identity from the migration owner. The runtime identity must not own schema objects, have schema CREATE privileges, alter the migration registry, or UPDATE/DELETE/TRUNCATE the audit trail. Default privileges should grant required DML on application tables to the runtime identity while keeping migration DDL authority with the migration identity. Existing deployments may need a DBA-led ownership/grant transition.

Regression coverage includes API startup using verification rather than migrations, read-only schema readiness verification, and PostgreSQL ACL checks that a non-owner runtime role cannot disable/drop audit triggers or replace the trigger function.

**Validation status: COMPLETE.** On 2026-10-14, the user confirmed 37 focused PostgreSQL migration/runtime-privilege/API tests passed, the full pytest suite completed at 100% without a skip summary, Ruff and `git diff --check` passed, and the package wheel built successfully on main commit `c39a7cd9d757e2a63cc27365e6e2b8e8a5e529b3`. Wheel SHA-256: `6867d9542088c520678beee241b1fd26ebc0fb73885ea6f4c16bbc5f4bf1fb25`. Five Starlette deprecation warnings were non-failing.

## Architecture Gate 59 — Fail-Closed Runtime Database Privilege Verification — COMPLETE

API startup calls `verify_runtime_privileges()` after read-only schema readiness verification and closes the connection on any failure. The verifier checks both `current_user` and `session_user`, superuser status, effective database/schema CREATE privileges, audit-table UPDATE/DELETE/TRUNCATE/TRIGGER privileges, migration-registry mutation privileges, and membership in protected-object owner roles. This detects inherited privileges and owner-role membership, not only direct grants.

**Validation status:** On 2026-10-14, the user confirmed 43 focused PostgreSQL migration/runtime-privilege/API tests passed, the full PostgreSQL-backed suite reached 100% without a reported failure or skip summary, Ruff and diff checks passed, and the package wheel built successfully on main commit `78f7856677d029c2f01d0000831b080e16c8f45c`. Wheel SHA-256: `f5315fe6366d53d9607e11aa1f4624978266c3e29a75376377bd17d03d63bb71`. Five Starlette deprecation warnings were non-failing.

## Architecture Gate 60 — Fail-Closed Runtime Ownership Boundary for Application Schema Objects — COMPLETE

Gate 59 checked ownership of the database, active schema, audit table, migration registry, and audit trigger function, but it did not enumerate ownership across all application-schema relations and routines. A runtime identity owning another table, view, sequence, routine, or user-defined type could retain destructive DDL authority even while protected-object checks passed.

Gate 60 extends the startup verifier to inspect ownership across every relation, routine, and type in the active application schema. It evaluates both `current_user` and `session_user` and inherited role membership, and fails closed when any such object is owned by the runtime identity or a role it can assume. It preserves read-only startup checks and the separately provisioned migration identity.

**Validation status: COMPLETE.** On 2026-10-14, the user confirmed the required PostgreSQL-focused tests, full PostgreSQL-backed suite, Ruff, diff check, and wheel build were clean and successful on main revision `080cc28ee38a207f3a5da83f36497510495a4a1a`.

## Architecture Gate 61 — Fail-Closed Runtime Relation Privilege Verification — COMPLETE

Gate 60 rejects runtime ownership of relations, routines, and types but does not inspect high-impact relation ACLs granted to non-owner roles. Gate 61 extends startup verification across ordinary and partitioned application tables and fails closed when either `current_user` or `session_user` has effective TRUNCATE, TRIGGER, or REFERENCES privilege, including inherited role grants. Application DML remains permitted according to the existing least-privilege deployment contract. The verifier remains read-only, and migrations remain in the separately controlled migration process.

PostgreSQL integration coverage grants each dangerous privilege independently on the ordinary `assets` table and asserts that runtime privilege verification rejects the role.

**Validation status: COMPLETE.** On 2026-10-14, the user confirmed all focused PostgreSQL migration/runtime privilege/API tests, the full PostgreSQL-backed suite, Ruff, diff check, and wheel build completed cleanly on main revision `0c6f22281f3242187ec2c1b3165b50557d9665d1`.

## Architecture Gate 62 — Fail-Closed Runtime Sequence Privilege Verification — COMPLETE

The current domain schema uses UUID-backed identifiers, so the runtime identity does not require sequence access. Gate 62 extends the read-only startup verifier to enumerate application-schema sequences and reject effective SELECT, USAGE, or UPDATE privileges granted to `current_user`, `session_user`, or inherited roles. This closes the sequence ACL gap without adding startup DDL or changing the controlled migration identity. PostgreSQL integration tests create an administrator-owned test sequence, grant each privilege separately to a genuine runtime login, and require fail-closed rejection. The least-privilege role must continue to pass.

**Validation closure:** On 2026-10-14, the user confirmed Gate 62 was clean and successful on main revision `3b7d25914b1866a2c9617940970b2d08a44f8463`.


## Architecture Gate 63 — Fail-Closed SECURITY DEFINER Routine Execution Verification — COMPLETE

The runtime verifier now rejects an effective EXECUTE privilege on any SECURITY DEFINER routine in the active application schema for either `current_user` or `session_user`, including inherited and PUBLIC grants. This prevents an otherwise non-owner runtime identity from invoking a routine that executes with elevated owner privileges. Ordinary invoker-security routines remain outside this specific restriction, and API startup remains read-only. A PostgreSQL integration regression creates an administrator-owned SECURITY DEFINER routine, grants execution to a genuine runtime login, and requires fail-closed rejection. The user confirmed Gate 63 clean and successful on 2026-10-14.

## Architecture Gate 64 — Authenticated SOC Workspace Read-Model Expansion — COMPLETE

The current UI exposes overview metrics, assets, findings, and scan activity while the API already provides authenticated campaign, evidence, attack-path relationship, and administrator-only audit read models. Gate 64 adds read-only sections for these existing contracts without inventing records or bypassing authorization. Evidence SHA-256 values and relationship validation states remain visible; audit access remains administrator-only.


## Architecture Gate 65 — Professional SOC Workspace Navigation & Accessibility — COMPLETE

The authenticated workspace now exposes overview, assets, findings, scan activity, campaigns, evidence, attack-path relationships, and the administrator-only audit read model. Its navigation active state must remain accurate while scrolling, and interactive elements must have visible keyboard focus. Gate 65 updates only presentation behavior: it uses existing same-origin anchors and DOM state, does not introduce inline scripts/styles, and does not change API authorization, session storage, or data contracts. CSS honors reduced-motion preferences and keeps the desktop sidebar usable while retaining horizontally scrollable mobile navigation.

The user confirmed Gate 65 clean and successful on 2026-10-14. This is user-confirmed validation; local test, PostgreSQL suite, Ruff, and wheel-build output were not independently executed in this environment.


## Architecture Gate 66 — Fail-Closed Runtime User-Identity Mutation Privilege Verification — COMPLETE

The PostgreSQL runtime privilege verifier rejects effective table-level INSERT, UPDATE, or DELETE privilege on the authentication `users` relation for either `current_user` or `session_user`, including inherited role and PUBLIC grants. User identity provisioning is outside the runtime API and belongs to a trusted deployment/admin workflow. The user confirmed Gate 66 clean and successful on 2026-10-14; this is user-confirmed validation.

## Architecture Gate 67 — Fail-Closed Runtime Column-Level User-Identity Mutation Privilege Verification — COMPLETE

The runtime privilege verifier rejects effective column-level INSERT or UPDATE grants on the authentication `users` relation for either `current_user` or `session_user`, including inherited and PUBLIC grants. The user confirmed Gate 67 clean and successful on 2026-10-14; this is user-confirmed validation.

## Architecture Gate 68 — Fail-Closed Handling of Invalid Persisted User Roles — COMPLETE

The authentication service maps unsupported persisted role values to the established fail-closed authentication/session errors. Login writes a denied audit event with a fixed generic detail and creates no session; existing sessions with an invalid role are rejected. The user confirmed Gate 68 clean and successful on 2026-10-14; this is user-confirmed validation.

## Architecture Gate 69 — Fail-Closed Handling of Corrupt Persisted Session Records — COMPLETE

Session authentication maps malformed persisted expiry timestamps and UUID identifiers to the established generic invalid-session response. Explicit inactive-user behavior and infrastructure exception visibility are preserved. The user confirmed Gate 69 clean and successful on 2026-10-14; this is user-confirmed validation.

## Architecture Gate 70 — Atomic Login Session and Success-Audit Persistence — COMPLETE

Successful login persists the authentication session and its success audit event through one repository transaction. If audit insertion fails, the transaction rolls back session creation, preventing an active session whose raw token was never returned. SQLite and PostgreSQL implementations and failure-injection regressions are included.

**Validation closure:** On 2026-10-14, the user confirmed focused API tests, the full PostgreSQL-backed pytest suite, Ruff, diff check, package wheel build, and final main synchronization were clean. Five Starlette deprecation warnings were non-failing. The optional `python -m build` command was unavailable because the module was not installed; the established pip wheel build was used instead. This is user-confirmed validation.

## Architecture Gate 71 — Atomic Logout Session Revocation and Success-Audit Persistence — COMPLETE

`AuthenticationService.logout()` calls `revoke_session_with_audit()`. The PostgreSQL implementation holds the repository transaction lock and commits session revocation plus the LOGOUT success audit event in one database transaction. The SQLite compatibility implementation uses one connection transaction and the repository transaction lock when available. SQLite and PostgreSQL failure-injection regressions assert an audit-write failure leaves the session unrevoked, then verify successful logout revokes it and writes one success event. On 2026-10-14, the user confirmed Gate 71 clean and successful; this is user-confirmed validation.

## Architecture Gate 72 — Atomic User Provisioning and Success-Audit Persistence — COMPLETE

`AuthenticationService.create_user()` delegates to `save_user_with_audit()`, atomically persisting the new user and USER_CREATED success audit event in one PostgreSQL transaction and one SQLite compatibility transaction. Failure-injection regressions verify audit insertion failure rolls back account creation. Password hashing, role validation, duplicate handling, and append-only audit protections remain unchanged. API test repositories implement the atomic user-and-audit contract.

**Validation closure:** On 2026-10-19, the user confirmed 20 focused authentication/storage tests passed, the full PostgreSQL-backed suite passed with 309 passed and 0 skipped (5 non-failing Starlette deprecation warnings), Ruff and `git diff --check` passed, and the package wheel built successfully. Wheel SHA-256: `eb66201f4e2622b35d262e399e12df464b58b014011be7ab54ac167575e98f49`. This is user-confirmed validation; the assistant did not independently run the local commands.

## Architecture Gate 73 — Atomic Login Rate-Limit Threshold Audit Persistence — COMPLETE

The login API previously called `record_login_attempts()` and then independently inserted `LOGIN_RATE_LIMITED` audit events when returned counters crossed the configured client or client/username thresholds. This left a persistence gap: an audit insert failure could occur after the counter transaction had already committed.

Gate 73 extends the PostgreSQL repository operation to accept per-bucket threshold metadata and insert the threshold-crossing audit event inside the same transaction as the counter changes. The API passes the existing 30-attempt client and 5-attempt identity limits and no longer performs a separate audit write. Only threshold crossings are audited, preserving bounded audit volume. Regression coverage includes API threshold behavior and PostgreSQL audit-failure rollback of the corresponding counter increment.

**Acceptance criteria:** counter and threshold audit event are atomic; repeated blocked attempts do not produce unbounded audit events; current rate-limit/Retry-After behavior is preserved; focused PostgreSQL and API tests, full PostgreSQL-backed suite without skips, Ruff, `git diff --check`, and package wheel build pass on the exact `main` revision.

**Validation status:** COMPLETE. On 2026-10-21, the user confirmed focused PostgreSQL/API tests and the full PostgreSQL-backed suite passed in Windows Python 3.15; Ruff and `git diff --check` passed; and the package wheel built successfully. Five Starlette deprecation warnings were non-failing. Wheel SHA-256: `ae82526e8bffef66a9e426f99ff20a2c5199091579aa32b644273a7bc234a565`. Validation was user-run and user-confirmed.

## Architecture Gate 74 — Python 3.15 Windows Dependency-Install Compatibility — COMPLETE

A clean Python 3.15 Windows install attempted to build PyYAML from source through the `uvicorn[standard]` dependency chain and failed without Microsoft C++ Build Tools. Gate 74 changes the dependency to Uvicorn core; code inspection found no use of optional YAML configuration, reload, or alternative HTTP/WebSocket implementations. A clean Python 3.15 dependency install and project wheel build succeeded; app imports passed in an isolated environment with PyYAML absent; Ruff and `git diff --check` passed. The user confirmed the full PostgreSQL-backed test suite passed with no skip summary; five Starlette deprecation warnings were non-failing.

## Architecture Gate 75 — Evidence-Backed Campaign Report Export — COMPLETE

The authenticated API now provides a JSON attachment for a selected campaign, backed by a dedicated PostgreSQL read model. Campaign findings are associated through finding evidence whose persisted execution provenance points to a scan in that campaign; evidence from other campaigns is excluded. The report contains campaign scope, scan-state counts, finding severity/state counts, bounded finding details, each finding's latest persisted risk assessment, and up to 20 campaign-scoped evidence references per finding. Raw evidence payloads are never returned. The report caps findings at 500 and marks finding/evidence truncation. The SOC dashboard provides a campaign selector and report download action.

**Validation status:** Thirty-three focused API/UI tests passed. On 2026-10-21, the user confirmed the report-specific PostgreSQL integration test and full PostgreSQL-backed suite completed at 100%; Ruff, `git diff --check`, and the Windows package wheel build passed. Five Starlette deprecation warnings were non-failing. Validation was user-run; changes remain local with no commit or push.

## Architecture Gate 76 — Auditable Campaign Report Export — COMPLETE

Gate 75 introduced an authenticated campaign report containing security-sensitive findings and evidence metadata. The download route currently returns this data without writing an audit event, so the append-only audit trail cannot attribute a successful export to its authenticated user.

`PostgresRepository.campaign_report_export_with_audit()` now assembles the bounded report and inserts a `CAMPAIGN_REPORT_EXPORTED` audit event in one transaction. The event contains the authenticated actor, campaign identifier, and bounded scan/finding summary metadata. The API returns a generic 503 and no report data if report/audit persistence fails; missing campaigns remain 404 without a success event. Existing READ authorization, campaign scoping, output bounds, raw-evidence exclusion, and response security headers are preserved. No schema migration was needed.

**Validation status:** The user confirmed the report-specific API and PostgreSQL tests and full suite reached 100%; Ruff and `git diff --check` passed; and the Windows package wheel built successfully on 2026-10-21. Five Starlette deprecation warnings were non-failing. Commit `e0dd2d9` (`Audit campaign report exports`) is on `main` and `origin/main`; validation is user-confirmed.

## Architecture Gate 77 — Secret Redaction in Evidence Metadata — COMPLETE

The evidence-list API returns persisted provider metadata. HTTP/API provider metadata includes target URLs and redirect locations; those values may contain secrets in query strings or fragments. A generic metadata map can also contain fields named for passwords, tokens, credentials, API keys, authorization, or signatures. Excluding raw evidence content alone does not prevent those values from appearing in the READ-authorized evidence response.

Gate 77 sanitizes metadata at the API response boundary: redact secret-like field names, strip URL userinfo, redact query strings, and remove fragments from URL-like metadata. Preserve safe provider/execution provenance and do not modify persisted evidence or its digest.

**Validation status:** On 2026-10-21, the user confirmed the focused evidence API test and full suite reached 100%, Ruff and `git diff --check` passed, and the Windows wheel built successfully. Five Starlette deprecation warnings were non-failing. Commit `9abd8a8` is on `main` and `origin/main`; validation was user-confirmed.

## Architecture Gate 78 — Retired: Organization Data Model

The user confirmed APM ThreatLens is a personal project and requested complete removal of multi-tenant organization and membership functionality from the GUI, backend, and database. The runtime uses local account roles and a single personal workspace. Migration 9 removes the legacy organization and membership tables plus ownership columns from campaigns, assets, evidence, and audit events, preserving assessment rows and the append-only audit trail. The runtime schema verifier fails startup if those legacy structures reappear.

Migration versions 4–8 remain in the ordered migration ledger because deployed databases already recorded their names and checksums. They are historical upgrade steps only; version 9 removes their structures from the active schema. Removing or editing their migration identities would prevent safe upgrades.

Keep user authentication, role authorization, explicit target authorization, scan scope enforcement, cancellation, and audit history. No organization or membership context is used.
## Architecture Gate 79 — Bounded Network Service Fingerprinting — COMPLETE

The built-in Network Scan checks bounded default TCP ports 22, 25, 80, and 443. For an open port among 22, 25, and 80, it performs one additional fixed probe: receive-only SSH/SMTP banner collection or HTTP `HEAD /`. `normalize_observation()` extracts protocol/product/version metadata; service version is persisted and bounded banner evidence is sealed through execution-fenced `ProviderHandoff`. SSH banners such as `OpenSSH_9.6p1` normalize to product `OpenSSH`, version `9.6p1`. HTTP evidence retains only the status and `Server` headers to avoid storing cookies or unrelated response headers. Cancellation is checked before the follow-up probe and response bytes are capped at 8192.

The provider tests use deterministic fake probes and cover service/version persistence plus evidence hash/provenance. On 2026-10-21, the user ran the full PostgreSQL-backed suite against `threatlens_test`; it reached 100% with five non-failing Starlette deprecation warnings. Ruff, `git diff --check`, and the Windows wheel build passed locally. No stealth, IDS/IPS evasion, or exploit payloads. This is an incremental capability and must not be presented as enterprise-scanner parity.

## Architecture Gate 80 — Personal Workspace and Database Cleanup — COMPLETE

The authenticated UI and runtime use a local user role without organization/membership context. PostgreSQL migration 9 removes legacy organization tables and ownership columns, restores global canonical-asset uniqueness, and preserves assessment records and append-only audit controls. Startup fails closed if those structures reappear. Versions 4–8 remain in the immutable migration ledger for upgrade compatibility; migration 9 removes their structures from the active schema. On 2026-10-21 the user confirmed migration success on `threatlens_dev` and a 100% full PostgreSQL-backed test run on `threatlens_test`; five Starlette deprecation warnings were non-failing.

## Architecture Gate 81 — Evidence-Backed Version-to-CVE Correlation — COMPLETE

Migrations 10–12 persist detected product and trusted intelligence. The NVD parser emits records only for explicit vulnerable exact-version CPE entries; rejected records, ranges, negated nodes, and compound AND nodes are skipped. A bounded HTTPS client calls only the official NVD host, disables redirects, caps responses at 2 MiB, enforces timeouts and process-wide request pacing, and reads an optional API key from the server environment. Admin-only `POST /api/v1/cve/ingest` transactionally stores records with an audit event; READ-authorized `GET /api/v1/cve` provides a bounded paginated read model. Network scans query exact product/version intelligence after service interrogation and emit only `SUSPECTED` findings tied to persisted service evidence through execution-fenced handoff. The provider persists the canonical service ID returned by PostgreSQL upserts. On 2026-10-23, the user confirmed migration success, the full PostgreSQL-backed suite reached 100%, Ruff and `git diff --check` passed, and the Windows wheel built; five Starlette deprecation warnings were non-failing. Matches remain candidates, not confirmed vulnerabilities.

## Architecture Gate 82 — Vendor-Aware CVE Matching — COMPLETE

NVD CPE vendor identity is retained alongside product and exact version. PostgreSQL migration 13 adds vendor fields, and migration 15 applies the vendor-aware intelligence key `(vulnerability_id, vendor, product)` without rewriting the already-applied migration 13 identity. SQLite also persists observed vendor metadata. Matching rejects candidates when observed and intelligence vendors conflict; an unknown observed vendor lowers confidence. Findings remain `SUSPECTED`. On 2026-10-23, the user confirmed migration recovery, full PostgreSQL tests at 100%, Ruff, diff checks, and the exact-source Windows wheel build (SHA-256 `afb0d9c0d913c942af975540774830b5059678ce77b742aacfe5bc376b8e9f22`).

## Architecture Gate 83 — Personal IOC Collection Import and Read API — COMPLETE

The API accepts bounded JSON imports for IPv4, IPv6, domains, and MD5/SHA-1/SHA-256 hashes. It canonicalizes values, rejects unsupported or malformed input, stores provenance/confidence/tags, and writes an audit event in the same transaction. ADMIN is required to import and READ to list, with pagination capped at 100 entries and an offset of 1,000,000. Import performs no DNS resolution, callbacks, lookups, or scans. CSV ingestion and UI integration remain later work. PostgreSQL migration 14 creates the IOC store; migration 15 applies the distinct vendor-aware CVE key. The user confirmed migrations, IOC API/PostgreSQL tests, the full suite after updating a stale migration-ledger expectation, Ruff, diff check, and wheel build (SHA-256 `0595d1aa0ef407be6d5063814fce8a5077a696ba1461ccc26fe77b87d7639d02`). The user also confirmed the latest full PostgreSQL-backed suite passed at 100% and Ruff passed, with six non-failing Starlette deprecation warnings.

## Architecture Gate 84 — Passive Web Security Posture Checks — COMPLETE

Improve useful Web Scan results using deterministic, evidence-backed checks against the already-authorized, bounded HTTP response. Checks cover Content-Security-Policy, Referrer-Policy, clickjacking protection, and Secure/HttpOnly/SameSite cookie attributes only when a session-like cookie is actually set. Preserve separate Set-Cookie header values, redact all cookie contents from evidence, and do not infer the presence of sensitive pages from a HEAD-only response. No redirect following, forms, fuzzing, payloads, or scope expansion. Validation and severity must distinguish confirmed header absence from contextual recommendations.

The user clarified that APM ThreatLens is currently a personal project. Prioritize useful Network Scan and Web Scan capability in this personal VAPT project. Keep the target-entry GUI simple and build scanner depth behind the existing provider/runtime/scope boundaries.

**Gate 84 validation:** On 2026-10-23, the user confirmed the exact source passed the full PostgreSQL-backed suite at 100% without a skip summary, Ruff, `git diff --check`, and a Windows wheel build (SHA-256 `815b6a24043acbd3586dd613f1b901aea83893a9ee2149c464ad97f5b54be8e4`). Six Starlette deprecation warnings were non-failing. An earlier attempted run without `THREATLENS_TEST_DATABASE_URL` skipped PostgreSQL tests; that was corrected before final validation.

## Architecture Gate 85 — Network Scan DNS Resolution Boundary — COMPLETE

Network Scan previously passed scoped FQDNs directly to TCP connect and service interrogation, allowing separate system DNS lookups for each probe without validating the returned addresses. Resolve each hostname once per execution; reject empty, malformed, oversized, private, reserved, loopback, or link-local answer sets before creating a socket; pin both the TCP check and follow-up service probe to the same validated IP; and retain the original FQDN as the authorized asset identity and HTTP Host value. Explicitly scoped literal private IPs remain available for authorized internal assessments. Evidence records both the authorized host and resolved IP. No schema migration or UI changes are needed.

**Validation closure:** The user confirmed the exact source passed the full PostgreSQL-backed suite at 100%, Ruff, `git diff --check`, and Windows wheel build (SHA-256 `983bfd20ec1c0fe2cbfa4795b1cdc40aa5859d72eef03a018dee77474ed31a9e`). Six Starlette deprecation warnings were non-failing.

## Architecture Gate 86 — Web/API Scan DNS Pinning — COMPLETE

Web/API assessment validates every DNS answer before sending requests and rejects empty or oversized answer sets. The transport connects directly to a validated address instead of resolving the hostname a second time. It retains the authorized hostname for the HTTP Host header and HTTPS SNI/certificate verification. Multicast and unspecified destinations are rejected even when private-address assessment is explicitly enabled. Existing response bounds, read-only methods, scope checks, and redirect suppression remain enforced.

Validation closure: On 2026-10-23, the user confirmed the full PostgreSQL-backed suite reached 100%, Ruff passed, `git diff --check` passed, and the Windows wheel built successfully (SHA-256 `58e7658678bab6ec3402cc1561bb26c1bba6898884a1040c4d079c630099369b`). Six Starlette deprecation warnings were non-failing.

## Architecture Gate 87 — TLS Scan DNS Pinning — COMPLETE

TLS assessment now resolves each scoped hostname once per execution, rejects empty, oversized, or disallowed answer sets before opening a socket, and pins the TLS connection to the validated address. The original hostname is retained for SNI and normal certificate hostname validation. Explicit literal private IPs remain supported for authorized internal scans; multicast and unspecified addresses remain prohibited. Default policy rejects non-public hostname answers, with an explicit policy option for internal hostname scans.

Validation closure: On 2026-10-23, the user confirmed the full PostgreSQL-backed suite reached 100%, Ruff and `git diff --check` passed, and the Windows wheel built successfully (SHA-256 `3e2a4638b7528d0b8e25d22194d6518658e50e764abdc791bb35c8acb23cde87`). Six Starlette deprecation warnings were non-failing.

## Architecture Gate 88 — Standalone Service Interrogation DNS Pinning — COMPLETE

The standalone active service interrogation provider must resolve each scoped hostname once, reject empty/oversized or disallowed non-public DNS answers before socket access, and pin its bounded banner probe to the validated IP. Preserve the original hostname for the fixed HTTP Host value and evidence identity. Explicit literal private IP targets remain available for authorized internal assessments. Preserve existing protocol, port, timeout, response-size, cancellation, and evidence-handoff controls.

Validation closure: On 2026-10-23, the user confirmed the full PostgreSQL-backed suite reached 100%, Ruff and `git diff --check` passed, and the Windows wheel built successfully (SHA-256 `42b21abcf780d08056024a084b476566e2567d6c603248b883fa3eecfe0db44c`). Six Starlette deprecation warnings were non-failing.

## Architecture Gate 89 — Network Scan TLS Observation Integration — COMPLETE

The default Network Scan now performs bounded TLS inspection only after a TCP-open result on ports 443 or 8443. It reuses the network provider's already validated and pinned destination address while retaining the scoped hostname for SNI and certificate validation. TLS evidence and deterministic policy findings use the established TLS provider metadata and ProviderHandoff sealing/execution fence. No additional target entry or scan UI was added.

Validation closure: On 2026-10-23, the user confirmed focused Network/TLS tests, the full PostgreSQL-backed suite at 100%, Ruff, `git diff --check`, and Windows wheel build (SHA-256 `b107e5b5c3bcb0d60a3f2d1fb9fa084737a6e9b6be3897124844fc32d3760bf0`). Six Starlette deprecation warnings were non-failing.

### UI usability and scan launch — locally implemented

The user requested a VAPT-first GUI with fixed top navigation/footer, working sidebar navigation, a target-only scan flow, and direct scan launch. For administrators, the local UI now presents one target field, explicit authorization confirmation, and a start button; it creates the authorized campaign and automatically selects the matching safe-by-default registered provider. Network target expansion is capped at 32 hosts. The current registered implementation still performs bounded TCP checks on its default ports or read-only HTTP observation; this is not yet the requested advanced scanner. Advanced network, web/API, cloud, and distributed capabilities remain roadmap items. UI/API tests pass locally; the user confirmed full PostgreSQL-backed validation of the single-user schema cleanup.

## Product Capability Roadmap and Security Boundaries

The README roadmap is the product target, not an implementation claim. Architecture work must preserve these boundaries as capabilities are added:

- **Authorized scope is mandatory.** Every provider action, redirect, DNS resolution, worker dispatch, imported endpoint, and callback must be checked against persisted allow-lists and exclusions. Revalidate immediately before network access; default-deny ambiguous or out-of-scope targets.
- **Network discovery is transparent and bounded.** TCP/UDP/permitted ICMP discovery, service/OS fingerprinting, CPE extraction, and traceroute must have explicit probe budgets, timeouts, and evidence provenance. Do not add decoys, fragmentation, source-port manipulation, firewall bypass, or IDS/IPS evasion.
- **Check modules are capabilities, not arbitrary code execution.** Require a reviewed manifest, version, declared permissions/effects, resource limits, isolation, and normalized evidence contract. No arbitrary user scripts execute in the API process.
- **Web/API checks are non-destructive by default.** Keep crawling same-scope and bounded; validate imported OpenAPI/Postman/GraphQL inputs; show request budgets; avoid modifying data or executing commands. OOB callbacks require an operator-owned service and explicit opt-in. RCE payload execution is out of scope.
- **Authentication secrets are protected.** Store profiles and tokens using a dedicated secret boundary, redact them from logs/evidence/reports, and never place credentials in browser storage or source control. Authorization testing must use explicit test identities.
- **Cloud/container checks are read-only and least-privilege.** Do not alter resources or probe cloud metadata endpoints. IaC analysis is local/static by default and must redact discovered secrets.
- **Distributed execution inherits authorization boundaries.** Queue records and workers must bind actor, campaign, scope, provider permissions, idempotency, cancellation, and audit context. No worker may trust a client-supplied target claim.
- **Reports preserve evidence quality.** Separate observed fact, inferred match, and validated vulnerability; include source/version/confidence and remediation; omit raw secrets and unsafe payloads.

The intended sequence is evidence-backed network/service capabilities, bounded web/API checks, trusted CVE/IOC ingestion, read-only cloud/container/IaC assessment, durable workers, CLI/CI integration, and expanded report formats. Every stage needs explicit scope enforcement, regression coverage, and validation before its status is marked complete. Gates 85–89 are complete; Gate 90 is in progress. No tenant model is in scope.

## Architecture Gate 90 — HTTP Response Evidence Minimization — IN PROGRESS

Web/API providers previously stored raw response excerpts and arbitrary headers in evidence, retained redirect destinations, and persisted target URLs with possible userinfo, query credentials, or fragments. Persist only an allowlist of at most 16 response headers with values capped at 512 characters (cookie values redacted; content-type parameters omitted), whether a redirect was observed, sanitized request URLs, and the response excerpt byte count plus SHA-256 digest. Do not persist the body or redirect destination. The API provider may continue using its bounded in-memory excerpt for the existing JSON validity check. The scanner's actual request target, authorization/scope checks, read-only methods, DNS pinning, response limits, and redirect suppression remain unchanged. Focused tests must verify sensitive URL/body/header/redirect values are absent from persisted evidence.
