# Advanced VAPT System — Master Development Instruction

This document governs implementation methodology and operational constraints.

## Source of Truth

For every development cycle:

CURRENT LATEST main
→ READ README.md
→ READ Architecture.md
→ READ MasterInstructions.md
→ DEEP INSPECT
→ PRIORITY ANALYSIS
→ ROOT CAUSE
→ SURGICAL CHANGE
→ TEST
→ SECURITY REVIEW
→ RE-INSPECT
→ STATUS
→ COMMIT
→ NEXT ARCHITECTURE GATE

Never rely on stale SHAs, prior conversations, screenshots, assumptions, or old implementation state.

## Required Engineering Principles

Build an integrated, evidence-driven VAPT orchestration platform covering authorized network, web, API, host, infrastructure, TLS, configuration, cloud/container, vulnerability intelligence, correlation, risk, attack paths, validation, evidence, remediation, campaign orchestration, and reporting.

The system must support explicit scoping and authorization.

Do not intentionally bypass authorization, compromise unrelated third-party systems, or indiscriminately scan the public Internet.

Do not fabricate evidence, telemetry, findings, progress, or validation.

Prefer surgical, production-grade changes. Avoid unnecessary dependencies and unrelated cleanup.

Preserve existing UI/design continuity unless a UI change is explicitly requested.

## Priority Order

1. Core backend architecture
2. Security architecture
3. Data integrity
4. Assessment orchestration
5. Telemetry and observability
6. Provider interfaces
7. Discovery
8. Network assessment
9. Web/API assessment
10. Vulnerability correlation
11. Risk engine
12. Attack-path analysis
13. Evidence management
14. Authentication/authorization
15. Reliability/performance
16. Frontend/UI/UX
17. Reporting
18. Documentation and cleanup

## Completion Standard

No architecture gate may be called complete without appropriate testing and explicit validation. If a validation step cannot be performed, state that fact.

## Cycle Report

At the end of each cycle report:

### IMPLEMENTED
Exact changes.

### WHY
Root cause and architectural reason.

### VALIDATION
Tests, build, lint, runtime checks.

### SECURITY REVIEW
Security implications and controls.

### ARCHITECTURE ALIGNMENT
README.md, Architecture.md, MasterInstructions.md.

### CURRENT STATUS
Verified state.

### NEXT ARCHITECTURE GATE
Exactly one highest-priority next objective.

### RECOMMENDATIONS
Only materially useful recommendations.
