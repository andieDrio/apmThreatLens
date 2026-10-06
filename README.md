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
- Provider protocol boundaries.
- Explicit campaign authorization and execution safety policy.
- Initial SQLite persistence boundary with database constraints and foreign-key integrity.
- Persisted scan execution IDs and fail-closed lifecycle transitions.
- Campaign/scan orchestration boundary with provider isolation and cancellation semantics.
- Provider registry with explicit metadata and capability declarations.
- Provider execution runtime with structured execution events, execution metrics, failure capture, and cooperative timeout/cancellation signaling.
- Evidence-first provider handoff with immutable evidence sealing, SHA-256 content integrity, execution/provider provenance, and finding/evidence validation.
- Controlled discovery provider that normalizes only authorized campaign targets, honors exclusions/cancellation, persists normalized assets, and records discovery evidence without claiming vulnerabilities or performing network probing.
- Automated persistence, orchestration, provider-runtime, evidence-handoff, and discovery tests.

### Current Architecture Gate

Architecture Gate 06: first controlled discovery provider. The current implementation is intentionally non-networking: it establishes scope-safe target normalization, asset identity, evidence provenance, exclusion handling, and cancellation behavior before any active probing backend is introduced.

### Validation Limitation

Repository changes are verified through GitHub. Local pytest, lint, build, and runtime execution must be performed in the development environment; no result is claimed here unless actually executed.

## Next Architecture Direction

The next priority is the discovery execution adapter boundary for controlled network enumeration. It must preserve the same authorization, exclusion, rate-limit, timeout, cancellation, provider-runtime, evidence, and asset-identity guarantees before any real network interaction is enabled.
