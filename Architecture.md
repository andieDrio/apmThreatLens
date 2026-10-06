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

## 9. Security

The platform itself is security-sensitive. Apply authentication, authorization, least privilege, secure secret handling, strict validation, output encoding, parameterized persistence operations, SSRF protections, path protections, secure command-execution boundaries, and comprehensive audit logging.

## 10. Architecture Gate 01

Establish the minimal production-grade backend/domain contract foundation required for later orchestration and provider implementations, without introducing fake scanner results or premature coupling to any one security tool.
