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
- Service identification and protocol metadata normalizer for bounded observations, with explicit protocol classification, product/version extraction, confidence, and banner-size limits. Identification remains an observation layer and does not create vulnerability claims.
- Controlled active service interrogation provider using only explicit, bounded protocol probes for authorized in-scope hosts, with target/port/response limits, cancellation, timeout, and evidence provenance.
- Controlled TLS assessment provider with bounded TLS handshake inspection, certificate metadata capture, hostname verification state, cipher/protocol observation, timeout/target limits, exclusion enforcement, cancellation, and evidence provenance.
- Deterministic TLS security-policy evaluation for deprecated TLS versions, certificate validation failures, hostname mismatch, certificate expiration, and weak/deprecated ciphers.
- End-to-end TLS finding handoff through persisted evidence, asset resolution, normalized finding validation, and the existing ProviderHandoff boundary.
- Automated persistence, orchestration, provider-runtime, evidence-handoff, discovery, network-discovery, identification, interrogation, TLS assessment, and TLS finding integration tests.

### Current Architecture Gate

Architecture Gate 11: TLS security-policy evaluation and finding integration. TLS observations are converted into deterministic, evidence-backed findings only after the observation has been sealed and persisted through ProviderHandoff. Findings must resolve to an authorized asset and reference the exact persisted evidence that triggered the rule.

### PostgreSQL Deployment Readiness

PostgreSQL is now a first-class deployment persistence target. The repository includes a PostgreSQL adapter and `.env.example`; local database installation and credentials remain deployment-environment responsibilities. The application does not auto-start or auto-create a database server.

For local development, install the Python dependencies after pulling the repository and configure `THREATLENS_DATABASE_URL` from `.env.example` without committing secrets.

### Validation Limitation

Repository changes are verified through GitHub. Local pytest, lint, build, PostgreSQL connectivity, and runtime execution must be performed in the development environment; no result is claimed here unless actually executed.

## Next Architecture Direction

The next priority is hardening the normalized finding contract for cross-provider correlation and deterministic deduplication, while preserving evidence provenance and preventing duplicate logical findings from multiple assessment providers.
