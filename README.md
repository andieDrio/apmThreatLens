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

- Foundational domain contracts for campaign, scope, asset, service, evidence, and finding.
- Provider protocol boundaries.
- Explicit campaign authorization and execution safety policy.
- Initial SQLite persistence boundary with database constraints and foreign-key integrity.
- Automated persistence tests covering relationships, deterministic asset identity, and orphan prevention.

### In Progress

Architecture Gate 02: persistent data-integrity architecture. The current SQLite adapter is the first implementation and remains intentionally isolated from provider-specific tooling.

### Validation Limitation

Repository changes are verified through GitHub. Local pytest, lint, build, and runtime execution must be performed in the development environment; no result is claimed here unless actually executed.

## Next Architecture Direction

After persistence contracts are stabilized, the next priority is the campaign/scan orchestration boundary, including lifecycle transitions, execution IDs, cancellation semantics, and provider execution isolation.
