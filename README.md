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
- SQLite persistence boundary with database constraints and foreign-key integrity.
- PostgreSQL persistence adapter using the same domain persistence boundary, with `psycopg` as the runtime driver.
- Persisted scan execution IDs and fail-closed lifecycle transitions.
- Campaign/scan orchestration boundary with provider isolation and cancellation semantics.
- Provider registry with explicit metadata and capability declarations.
- Provider execution runtime with structured execution events, execution metrics, failure capture, and cooperative timeout/cancellation signaling.
- Evidence-first provider handoff with immutable evidence sealing, SHA-256 content integrity, execution/provider provenance, and finding/evidence validation.
- Controlled discovery provider that normalizes only authorized campaign targets, honors exclusions/cancellation, persists normalized assets, and records discovery evidence without claiming vulnerabilities or performing network probing.
- Controlled TCP network discovery adapter with explicit host allowlisting through campaign scope, exclusion enforcement, bounded target count, bounded ports, per-connect timeout, cooperative cancellation, service normalization, and evidence provenance.
- Automated persistence, orchestration, provider-runtime, evidence-handoff, discovery, and network-discovery tests.

### Current Architecture Gate

Architecture Gate 07: controlled TCP network discovery adapter. Active network interaction is limited to explicitly scoped IP/FQDN targets and a bounded explicit port set. CIDR expansion, UDP probing, exploitation, and unrestricted scanning are intentionally outside this gate.

### PostgreSQL Deployment Readiness

PostgreSQL is now a first-class deployment persistence target. The repository includes a PostgreSQL adapter and `.env.example`; local database installation and credentials remain deployment-environment responsibilities. The application does not auto-start or auto-create a database server.

For local development, install the Python dependencies after pulling the repository and configure `THREATLENS_DATABASE_URL` from `.env.example` without committing secrets.

### Validation Limitation

Repository changes are verified through GitHub. Local pytest, lint, build, PostgreSQL connectivity, and runtime execution must be performed in the development environment; no result is claimed here unless actually executed.

## Next Architecture Direction

The next priority is service identification and protocol metadata normalization over the controlled network-discovery results, while preserving scope, evidence provenance, and the distinction between observed service exposure and vulnerability claims.
