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

## 7. Risk Boundary

Risk must be explainable and must not depend exclusively on CVSS. Environmental context, exploitability, exposure, asset criticality, business impact, threat relevance, control coverage, and confidence are relevant inputs.

## 8. Data Integrity

Use explicit identifiers, lifecycle states, timestamps, provenance, and database/application constraints appropriate to the selected persistence technology. Correlation must remain deterministic and auditable.

The current persistence boundary uses SQLite for the dependency-free initial implementation. Its schema enforces foreign keys, unique asset canonical identity, service uniqueness per asset/protocol/port, finding/evidence relationships, and bounded CVSS/confidence values.

## 9. Campaign / Scan Orchestration

Campaign execution is represented by a persisted Scan with a unique execution ID and provider identity. Lifecycle transitions are fail-closed:

QUEUED → RUNNING → COMPLETED | FAILED | CANCELLED | PARTIAL

A queued execution may also be cancelled before provider execution. Terminal states cannot transition again. The orchestrator validates authorization and execution policy before queueing, persists lifecycle changes, isolates provider execution behind a protocol, and passes a cancellation event to the provider.

The persistence layer is authoritative for lifecycle state; orchestration must not infer completion solely from in-memory execution.

## 10. Security

The platform itself is security-sensitive. Apply authentication, authorization, least privilege, secure secret handling, strict validation, output encoding, parameterized persistence operations, SSRF protections, path protections, secure command-execution boundaries, and comprehensive audit logging.

## 11. Architecture Gate 01

Establish the minimal production-grade backend/domain contract foundation required for later orchestration and provider implementations, without introducing fake scanner results or premature coupling to any one security tool.

## 12. Architecture Gate 02

Establish the persistent data-integrity boundary for Campaign → Scope → Asset → Service → Finding → Evidence. The current SQLite repository is the initial implementation of this boundary; provider execution and higher-level orchestration must depend on repository contracts rather than direct SQL access.

## 13. Architecture Gate 03

Establish the campaign/scan orchestration boundary with execution IDs, explicit lifecycle transitions, cancellation semantics, provider isolation, and persisted authoritative execution state. Actual scanner/provider implementations remain out of scope for this gate.
