# APM ThreatLens — Project Status

**Last updated:** 2026-10-14  
**Source of truth:** GitHub `main`  
**Highest architecture gate reached:** Gate 54  
**Current gate:** Gate 54 — Versioned PostgreSQL Schema Migrations  
**Current status:** Implementation committed to main; local PostgreSQL validation pending

## Executive Summary

APM ThreatLens is an authorized VAPT orchestration platform with PostgreSQL persistence, authenticated scan lifecycle controls, controlled assessment providers, evidence-first handoff, finding correlation, risk assessment, attack-path analysis, evidence validation, remediation tracking, audit read models, and an initial authenticated dashboard.

Gates 49–51 remain complete based on prior user-confirmed validation. Gate 52's PostgreSQL execution-fence regression tests and Gate 53's API/PostgreSQL remediation-idempotency tests were confirmed executed successfully on 2026-10-14: the full suite reached 100% without a skip summary, focused remediation tests passed (9 API tests and 5 PostgreSQL tests), Ruff passed, diff checks were clean, and the package wheel built successfully. Five Starlette deprecation warnings remain non-blocking.

## Current Gate — Gate 54: Versioned PostgreSQL Schema Migrations

### Objective and root cause

Replace implicit, scattered PostgreSQL schema initialization with a durable, ordered migration registry. Previously, the initial schema, additive column changes, authentication, finding correlation, evidence validation, and remediation-idempotency tables were initialized through separate code paths without a central record of applied schema versions.

### Implementation on main

- Added `src/threatlens/storage/schema_migrations.py` with ordered migration definitions and the `threatlens_schema_migrations` registry.
- Serialized migration execution across application instances using a stable PostgreSQL session advisory lock.
- Added migration name/checksum verification, history-gap detection, and fail-closed handling for unknown future versions.
- Adopted the existing initializer as retry-safe baseline migration version 1.
- Required new migrations to be append-only and transactional wherever supported.
- Routed `PostgresRepository.initialize()` through the migration runner and retained the existing DDL in `_initialize_legacy_schema()`.
- Added PostgreSQL tests for baseline adoption, repeat initialization/data preservation, migration failure/retry, and concurrent initialization.

### Relevant files

- `src/threatlens/storage/schema_migrations.py`
- `src/threatlens/storage/postgres.py`
- `tests/test_postgres_schema_migrations.py`
- `README.md`
- `Architecture.md`
- `MasterInstructions.md`
- `PROJECT_STATUS.md`

### Validation

Gate 54 implementation is committed to `main`. Local PostgreSQL-backed tests, the full suite, Ruff, diff checks, and wheel build for this revision remain unconfirmed. Run the validation commands against the dedicated disposable PostgreSQL test database before marking the gate complete.

### Security and recovery review

- The migration registry identifier is validated before SQL interpolation; migration values are parameterized.
- Session-level advisory locking survives commits in the legacy baseline, preventing concurrent app instances from racing through schema setup.
- The baseline is explicitly non-transactional because existing initialization helpers commit internally; the DDL is idempotent and safe to retry if version registration fails.
- New migrations run transactionally with their version record, so a failed migration is not marked applied.
- Unknown future versions, version gaps, and applied migration identity/checksum drift fail closed.
- No existing application data is rewritten by this baseline adoption.

## Recent Completed Gates

| Gate | Improvement | Status |
|---|---|---|
| 49 | Durable cross-instance scan-queue idempotency; replay returns original execution, conflicting key reuse rejected | Complete — user-confirmed validation |
| 50 | Durable idempotency for cancellation and stale-recovery commands; atomic command result and audit | Complete — user-confirmed validation |
| 51 | Fail-closed heartbeat lease handling, cooperative cancellation on lease loss, and heartbeat-worker shutdown | Complete — user-confirmed validation |
| 52 | Execution-lease-fenced evidence/finding persistence and fail-closed compatibility behavior | Validation commands pass; review skipped PostgreSQL-backed tests before completion |

## Broader Capability Improvements Recorded in Repository

- PostgreSQL is the canonical production and active integration-test persistence path.
- Authenticated application APIs for campaign/scope control, scan lifecycle control, findings, evidence, risk assessments, attack-path relationships/analysis, and security audit read models.
- Cross-instance scan command idempotency and retry/recovery serialization.
- Durable heartbeat leases, stale recovery, lifecycle compare-and-set transitions, bounded provider concurrency, and atomic audit/lifecycle writes.
- Controlled discovery, TCP service discovery/interrogation, TLS, web, and API assessment providers with explicit scope and bounded behavior.
- Evidence sealing with SHA-256, provenance-aware handoff, durable finding correlation, vulnerability intelligence normalization/matching, and context-aware correlation.
- Risk assessment and validated evidence-backed attack-path analysis.
- Initial authenticated, read-only dashboard UI with restrictive response security headers.

## Feedback and Recommendations

1. Run `python -m pytest -q -rs` and confirm the PostgreSQL-backed execution-fence regression tests were not skipped.
2. Keep generated Python bytecode/build artifacts out of commits. The repository currently tracks some `.pyc` files, so tests may modify them; clean them before checking final Git status.
3. Consider a dedicated follow-up cleanup to stop tracking generated `__pycache__`/`.pyc` artifacts and add/verify ignore rules. Do not mix that cleanup into Gate 52 unless it is necessary to validate this gate.
4. After Gate 52's required PostgreSQL-backed tests are confirmed executed, re-fetch latest `main`, inspect the architecture and implementation, and select the next highest-priority unfinished gap.


## Gate 52 and Gate 53 Validation Closure

### Gate 52 — Execution-Lease-Fenced Evidence and Finding Persistence — COMPLETE

On 2026-10-14, the user confirmed the PostgreSQL-backed full test suite completed at 100% with no skip summary, along with clean Ruff and diff checks and a successful package wheel build. The run included the PostgreSQL integration tests, resolving the prior skip-review blocker.

### Gate 53 — Durable Finding Remediation Idempotency — COMPLETE

On 2026-10-14, the user confirmed 9 focused API tests and 5 focused PostgreSQL remediation tests passed. The full test suite reached 100%, Ruff and diff checks were clean, and the package wheel built successfully.

The five Starlette deprecation warnings about `HTTP_422_UNPROCESSABLE_ENTITY` were non-failing warnings.

## Next Required Action

Validate Gate 54 — Versioned PostgreSQL Schema Migrations — against the exact current `main` revision using focused PostgreSQL tests, `python -m pytest -q -rs`, `ruff check .`, `git diff --check`, and `python -m pip wheel . --no-deps --wheel-dir /tmp/apm-threatlens-wheel`. Do not mark Gate 54 complete until the test output confirms the PostgreSQL migration regressions actually executed.
