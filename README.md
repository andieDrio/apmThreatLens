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
- Automated persistence and orchestration tests covering relationships, deterministic asset identity, lifecycle transitions, provider failure, cancellation, and terminal-state protection.

### Current Architecture Gate

Architecture Gate 03: campaign/scan orchestration. The current implementation is deliberately provider-neutral; no real scanner is invoked by the orchestration tests.

### Validation Limitation

Repository changes are verified through GitHub. Local pytest, lint, build, and runtime execution must be performed in the development environment; no result is claimed here unless actually executed.

## Next Architecture Direction

The next priority is the provider execution contract and execution observability boundary: provider registration/capabilities, execution metadata, structured events, failure classification, timeout/cancellation propagation, and evidence/finding handoff without coupling orchestration to a specific scanner.
