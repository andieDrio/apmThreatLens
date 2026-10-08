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

- Organization
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

The repository contains `.env.example` with a non-secret `THREATLENS_DATABASE_URL` template. Real credentials must remain outside version control. Local PostgreSQL installation, service lifecycle, database creation, and credential provisioning are deployment responsibilities and must not be silently automated by the application.

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

The API factory accepts injected repository and authentication services, keeping transport concerns separate from persistence and domain contracts and making the boundary testable without weakening production PostgreSQL requirements. The production entrypoint initializes the canonical PostgreSQL repository from THREATLENS_DATABASE_URL.

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

**Validation status:** Gate 39 implementation and tests are committed. Local PostgreSQL-backed `pytest -q` and `ruff check .` are required before Gate 39 can be declared complete.
