# APM ThreatLens — Project Status

**Last updated:** 2026-10-13  
**Source of truth:** GitHub `main`  
**Highest architecture gate reached:** Gate 53  
**Current gate:** Gate 53 — Durable Idempotency for Finding Remediation Commands  
**Current status:** Gate 52 validated; Gate 53 implementation on working branch, validation pending

## Executive Summary

APM ThreatLens is an authorized VAPT orchestration platform with a PostgreSQL-backed persistence boundary, authenticated scan lifecycle controls, controlled assessment providers, evidence-first handoff, finding correlation, risk assessment, attack-path analysis, evidence validation, remediation tracking, audit read models, and an initial authenticated dashboard.

The highest numbered gate reached is 53. Gate numbering includes historical and differently validated entries. Gates 49–51 were previously confirmed complete. On 2026-10-13, the user confirmed all nine focused execution-fence tests passed, including the PostgreSQL-backed cases, completing Gate 52 validation. Gate 53 is being implemented on branch `gate-53-remediation-idempotency`; it is not complete until validation results are available.

## Completed Gate — Gate 52

### Objective

Prevent provider-originated evidence and findings from persisting after their scan execution loses its durable `RUNNING` lease, and fail closed if the production persistence boundary cannot enforce that lease.

### Root cause

The normal PostgreSQL execution-aware methods fenced provider writes, but generic/legacy compatibility fallbacks remained available when a repository lacked the execution-fenced methods. A production adapter misconfiguration or future refactor could accidentally select an unfenced handoff path.

### Implemented changes

- `PostgresRepository` declares `requires_execution_fence = True`.
- `ProviderHandoff` rejects unfenced evidence or finding fallback when the repository requires execution fencing.
- `ProviderHandoff` refuses a correlator fallback if the repository requires the fence but the correlator lacks an execution-aware persistence method.
- `DurableFindingCorrelator.persist_for_execution` fails closed when a fence-required repository does not expose the execution-aware correlation method.
- PostgreSQL generic `save_evidence` rejects evidence carrying execution provenance; execution-bound evidence must use `save_evidence_for_execution`.
- Execution-aware PostgreSQL evidence and finding writes continue to lock the scan row, require `RUNNING`, and write in the same transaction. Durable correlation takes the same scan-row lock before correlation/merge persistence.
- Added regression tests for missing-fence fallbacks and attempts to persist execution-bound evidence through the unfenced method.
- Updated `README.md`, `Architecture.md`, and `MasterInstructions.md` to record the security hardening and make this report mandatory for future cycles.

### Relevant files

- `src/threatlens/providers/handoff.py`
- `src/threatlens/storage/postgres.py`
- `src/threatlens/storage/finding_correlation.py`
- `tests/test_provider_handoff_execution_fence.py`
- `README.md`
- `Architecture.md`
- `MasterInstructions.md`
- `PROJECT_STATUS.md`

### Validation

**Baseline before the latest fail-closed changes:** user confirmed the following passed on the preceding revision:
- `ruff check .`
- `git diff --check`
- `python -m pytest -q`
- `python -m pip wheel . --no-deps --wheel-dir /tmp/apm-threatlens-wheel`

The full test run reported five Starlette deprecation warnings for `HTTP_422_UNPROCESSABLE_ENTITY`; no test failures were reported.

**Latest revision:** the user reported successful Ruff, diff checks, pytest command, and wheel build. The test suite contained many skipped tests and five Starlette deprecation warnings, with no failures. The skip summary is needed to establish whether the required PostgreSQL-backed execution-fence regressions executed.

### Security review

- **Improved:** production handoff/correlation fallback is fail-closed when the repository explicitly requires execution fencing.
- **Improved:** execution-bound evidence cannot be sent through the generic PostgreSQL evidence-write method.
- **Preserved:** scan-row lock and `RUNNING` state verification share the persistence transaction, serializing provider writes against cancellation/recovery/terminal transitions.
- **Compatibility:** legacy and in-memory repositories can retain unfenced fallback only when they do not declare that execution fencing is mandatory.
- **Call-path review:** inspected all 15 provider source modules on `main`; the only direct `save_evidence`, `save_finding`, or legacy `persist` calls were the compatibility branches inside `ProviderHandoff`. No provider module was found writing directly around that boundary.
- **Still to verify:** local tests against the exact latest `main` revision.

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


## Gate 52 Main-Branch Change References

The following implementation and report commits were pushed directly to `main` during this cycle:

- `c9aa400` — fail closed on unfenced provider handoff
- `06e6e6e` — guard unfenced execution evidence writes
- `96176aa` — require fenced durable finding correlation
- `0c66c72`, `59f6397`, `bead258`, `c699bd6` — regression tests and test cleanup
- `e4281df` — README Gate 52 status
- `322714a` — Architecture.md Gate 52 security hardening
- `8f86db0` — require per-cycle project status reporting
- `f8e57d3` — add this living project status report

The user confirmed successful local validation on 2026-10-13 after the latest implementation and regression-test commits.

## Next Required Action

Gate 52 validation is complete after the user confirmed all nine focused execution-fence tests passed, including PostgreSQL-backed cases. Gate 53 is now the active implementation and must be validated before any further gate is selected.


## Current Gate — Gate 53: Durable Idempotency for Finding Remediation Commands

### Objective

Make remediation retries safe across application instances without creating duplicate state transitions or audit events.

### Implemented on working branch

- The remediation endpoint requires a bounded safe-ASCII `Idempotency-Key` and emits `Idempotency-Replayed`.
- The request fingerprint binds finding ID, target state, and rationale.
- PostgreSQL serializes actor/key requests using a transaction-scoped advisory lock and stores the original result durably.
- Exact retries return the stored result; conflicting reuse returns HTTP 409.
- The existing remediation transition and audit operation remains the authoritative mutation boundary.
- API and PostgreSQL regression tests cover key enforcement, replay, audit stability, and conflicts.

### Validation status

**Pending.** Changes are on the working branch only. Ruff, `git diff --check`, focused tests, the full test suite, PostgreSQL integration tests, and wheel build have not been run by this assistant environment. Do not merge or mark Gate 53 complete until the user runs and confirms these checks.

## Next Required Action

Fetch the latest branch, inspect the diff, fix all lint/test/runtime failures in Gate 53, then run focused PostgreSQL tests, the full suite, Ruff, diff checks, and package build. Do not start Gate 54 until Gate 53 is fully validated and explicitly confirmed.
