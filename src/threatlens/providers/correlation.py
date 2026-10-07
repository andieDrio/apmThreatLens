"""Deterministic cross-provider finding correlation and deduplication."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import replace
from enum import IntEnum
from uuid import NAMESPACE_URL, uuid5

from threatlens.domain.models import Finding, FindingState


class _SeverityRank(IntEnum):
    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


_STATE_RANK: dict[FindingState, int] = {
    FindingState.SUSPECTED: 1,
    FindingState.LIKELY: 2,
    FindingState.CONFIRMED: 3,
    FindingState.INFORMATIONAL: 1,
    FindingState.NOT_REPRODUCIBLE: 0,
    FindingState.FALSE_POSITIVE: 0,
    FindingState.ACCEPTED_RISK: 0,
    FindingState.MITIGATED: 0,
}


def correlation_key(finding: Finding) -> str:
    """Return a deterministic logical identity including explicit assessment context."""
    if finding.vulnerability_id:
        identity = f"vuln:{_normalize(finding.vulnerability_id)}"
    else:
        identity = f"title:{_normalize(finding.title)}|cwe:{_normalize(finding.cwe or '')}"
    context = (
        f"service:{_uuid_or_empty(finding.service_id)}"
        f"|endpoint:{_normalize_optional(finding.endpoint)}"
        f"|parameter:{_normalize_optional(finding.parameter)}"
        f"|location:{_normalize_optional(finding.location)}"
    )
    return f"asset:{finding.asset_id}|{identity}|{context}"


def correlate_findings(findings: tuple[Finding, ...] | list[Finding]) -> tuple[Finding, ...]:
    """Merge equivalent findings while retaining every unique evidence reference.

    Correlation is conservative: explicit service, endpoint, parameter, and location
    context is part of identity, and missing context never matches supplied context.
    Findings with different asset IDs cannot correlate.
    """
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[correlation_key(finding)].append(finding)

    correlated: list[Finding] = []
    for key, group in sorted(groups.items()):
        representative = max(
            group,
            key=lambda item: (
                _SeverityRank[item.severity.value],
                _STATE_RANK[item.state],
                item.confidence,
                item.detected_at,
                str(item.id),
            ),
        )
        evidence_ids = tuple(
            dict.fromkeys(evidence_id for item in group for evidence_id in item.evidence_ids)
        )
        sources = tuple(sorted({item.source for item in group if item.source}))
        logical_id = uuid5(NAMESPACE_URL, f"threatlens:finding:{key}")
        merged_source = ",".join(sources) if sources else representative.source
        merged_confidence = max(item.confidence for item in group)
        correlated.append(
            replace(
                representative,
                id=logical_id,
                evidence_ids=evidence_ids,
                source=merged_source,
                confidence=merged_confidence,
            )
        )
    return tuple(correlated)


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().casefold())


def _normalize_optional(value: str | None) -> str:
    return _normalize(value) if value is not None else ""


def _uuid_or_empty(value) -> str:
    return str(value) if value is not None else ""
