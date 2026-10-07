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
- Deterministic cross-provider finding correlation using asset identity plus vulnerability identity (or normalized title/CWE fallback), with stable logical finding IDs and preservation of all unique evidence and contributing provider sources.
- Automated persistence, orchestration, provider-runtime, evidence-handoff, discovery, network-discovery, identification, interrogation, TLS assessment, TLS finding integration, finding-correlation, risk-engine, attack-path, and evidence-validation tests.

### Current Architecture Gate

Architecture Gate 17: Authentication and Authorization. Raw evidence remains immutable and SHA-256 sealed. Validation is an explicit append-only lifecycle with PENDING → VALIDATED/REJECTED and terminal SUPERSEDED handling; validation decisions require traceability to persisted evidence and re-check stored evidence integrity before acceptance. Raw evidence is never rewritten by validation.

### PostgreSQL Deployment Readiness

PostgreSQL is now a first-class deployment persistence target. The repository includes a PostgreSQL adapter and `.env.example`; local database installation and credentials remain deployment-environment responsibilities. The application does not auto-start or auto-create a database server.

For local development, install the Python dependencies after pulling the repository and configure `THREATLENS_DATABASE_URL` from `.env.example` without committing secrets.

### Validation Limitation

Repository changes are verified through GitHub. Local pytest, lint, build, PostgreSQL connectivity, and runtime execution must be performed in the development environment; no result is claimed here unless actually executed.

## Architecture Gate 17 Status

Authentication is now a first-class backend boundary. Users use PBKDF2-HMAC-SHA256 password hashes, successful logins receive short-lived opaque sessions whose hashes are persisted, revoked sessions fail closed, role permissions are explicit, authentication/authorization decisions are audited, and assessment orchestration requires an authenticated principal with ASSESS permission. Viewer principals cannot execute assessments. SQLite and PostgreSQL persist users, sessions, and audit events without storing raw session tokens.

## Next Architecture Direction

The next priority is reliability and performance hardening of the authenticated execution boundary and persistence operations.
