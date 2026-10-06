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
- Automated persistence, orchestration, provider-runtime, and evidence-handoff tests.

### Current Architecture Gate

Architecture Gate 05: evidence and finding handoff. Raw evidence is kept conceptually separate from normalized findings; provider output must be bound to execution/provider provenance before persistence.

### Validation Limitation

Repository changes are verified through GitHub. Local pytest, lint, build, and runtime execution must be performed in the development environment; no result is claimed here unless actually executed.

## Next Architecture Direction

The next priority is the first controlled discovery provider, which must consume authorized campaign scope, execute through the provider registry/runtime, normalize discovered assets, persist evidence where applicable, and preserve execution provenance. Real network interaction must remain explicitly scoped and safety-controlled.
