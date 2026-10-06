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

SQLite remains the dependency-light local test persistence implementation. PostgreSQL is now a first-class deployment persistence target through `PostgresRepository`, using the same domain repository methods and equivalent integrity constraints. PostgreSQL connection details are deployment configuration; the application does not auto-start or auto-create a database server.

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

## 15. PostgreSQL Deployment Boundary

PostgreSQL is a supported production persistence backend through `PostgresRepository`. The schema mirrors the current domain integrity requirements: foreign keys, unique canonical asset identity, service uniqueness per asset/protocol/port, finding/evidence relationships, scan execution identity, and bounded CVSS/confidence values.

The repository contains `.env.example` with a non-secret `THREATLENS_DATABASE_URL` template. Real credentials must remain outside version control. Local PostgreSQL installation, service lifecycle, database creation, and credential provisioning are deployment responsibilities and must not be silently automated by the application.

## 16. Security

The platform itself is security-sensitive. Apply authentication, authorization, least privilege, secure secret handling, strict validation, output encoding, parameterized persistence operations, SSRF protections, path protections, secure command-execution boundaries, and comprehensive audit logging.

## 17. Architecture Gate 01

Establish the minimal production-grade backend/domain contract foundation required for later orchestration and provider implementations, without introducing fake scanner results or premature coupling to any one security tool.

## 18. Architecture Gate 02

Establish the persistent data-integrity boundary for Campaign → Scope → Asset → Service → Finding → Evidence. The current SQLite repository is the initial implementation of this boundary; provider execution and higher-level orchestration must depend on repository contracts rather than direct SQL access.

## 19. Architecture Gate 03

Establish the campaign/scan orchestration boundary with execution IDs, explicit lifecycle transitions, cancellation semantics, provider isolation, and persisted authoritative execution state. Actual scanner/provider implementations remain out of scope for this gate.

## 20. Architecture Gate 04

Establish provider registration, capability metadata, execution context, structured execution events, runtime metrics, provider failure capture, and cooperative timeout/cancellation signaling. Real scanner integrations remain out of scope until evidence/finding handoff contracts are established.

## 21. Architecture Gate 05

Establish the evidence/finding handoff boundary: immutable evidence sealing, content integrity, execution/provider provenance, evidence-backed normalized findings, asset identity validation, and rejection of findings that cannot be traced to supplied evidence.

## 22. Architecture Gate 06

Establish the first controlled discovery provider. The initial implementation must normalize explicitly scoped targets, honor exclusions and cancellation, persist assets with deterministic canonical identity, and preserve discovery evidence/provenance without performing network probing or generating vulnerability claims.

## 23. Architecture Gate 07

Establish the controlled network discovery adapter. The implementation must perform only bounded TCP connection discovery against explicitly scoped IP/FQDN targets, enforce exclusions and target/port/time limits, honor cancellation, normalize positive services, preserve raw evidence/provenance, and never convert service exposure into a vulnerability claim. PostgreSQL deployment readiness is included as a persistence backend so later backend deployment does not require a storage-contract rewrite.

## 24. Architecture Gate 08

Establish service identification and protocol metadata normalization over bounded provider observations. The implementation must normalize protocol, service, product, version, and confidence without unsupported guessing; preserve bounded raw banner context; remain evidence-traceable; and keep service identification separate from vulnerability assessment. Active application-payload interrogation remains behind the next explicit execution gate.
