"""Deterministic, evidence-backed attack-path analysis.

This module does not discover connectivity or infer trust relationships. A
caller must provide explicit directional relationships, evidence references,
validated state, entry assets, and objective assets. The analyzer only walks
validated relationships and reports paths that can be reproduced from those
inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import NAMESPACE_URL, UUID, uuid5

from threatlens.domain.models import Finding


class AttackPathRelationType(StrEnum):
    NETWORK_REACHABILITY = "NETWORK_REACHABILITY"
    TRUST_RELATIONSHIP = "TRUST_RELATIONSHIP"
    APPLICATION_FLOW = "APPLICATION_FLOW"
    AUTHENTICATED_ACCESS = "AUTHENTICATED_ACCESS"
    OTHER = "OTHER"


@dataclass(frozen=True, slots=True)
class AttackPathRelation:
    source_asset_id: UUID
    target_asset_id: UUID
    relationship_type: AttackPathRelationType
    evidence_ids: tuple[UUID, ...]
    validated: bool = False
    id: UUID | None = None

    def __post_init__(self) -> None:
        if self.source_asset_id == self.target_asset_id:
            raise ValueError("attack-path relationship cannot target itself")
        if not self.evidence_ids:
            raise ValueError("attack-path relationship must reference evidence")
        if self.id is None:
            object.__setattr__(
                self,
                "id",
                uuid5(
                    NAMESPACE_URL,
                    "threatlens:attack-relation:"
                    f"{self.source_asset_id}:{self.target_asset_id}:"
                    f"{self.relationship_type.value}:"
                    + ",".join(sorted(str(item) for item in self.evidence_ids)),
                ),
            )


@dataclass(frozen=True, slots=True)
class AttackPath:
    asset_ids: tuple[UUID, ...]
    relation_ids: tuple[UUID, ...]
    finding_ids: tuple[UUID, ...]
    score: float
    risk_level: str
    explanation: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AttackPathResult:
    paths: tuple[AttackPath, ...]
    ignored_relation_ids: tuple[UUID, ...]


class AttackPathAnalyzer:
    """Analyze only explicitly supplied, validated, evidence-backed graph edges."""

    def analyze(
        self,
        *,
        entry_asset_ids: tuple[UUID, ...] | list[UUID],
        objective_asset_ids: tuple[UUID, ...] | list[UUID],
        relations: tuple[AttackPathRelation, ...] | list[AttackPathRelation],
        findings: tuple[Finding, ...] | list[Finding],
        risk_scores: dict[UUID, float] | None = None,
        risk_levels: dict[UUID, str] | None = None,
        max_hops: int = 8,
        max_paths: int = 100,
    ) -> AttackPathResult:
        if max_hops < 1:
            raise ValueError("max_hops must be at least 1")
        if max_paths < 1:
            raise ValueError("max_paths must be at least 1")

        entries = tuple(sorted(set(entry_asset_ids), key=str))
        objectives = set(objective_asset_ids)
        if not entries:
            raise ValueError("at least one entry asset is required")
        if not objectives:
            raise ValueError("at least one objective asset is required")

        finding_by_asset: dict[UUID, list[Finding]] = {}
        for finding in findings:
            finding_by_asset.setdefault(finding.asset_id, []).append(finding)

        usable: list[AttackPathRelation] = []
        ignored: list[UUID] = []
        for relation in relations:
            if relation.validated and relation.evidence_ids:
                usable.append(relation)
            else:
                ignored.append(relation.id)  # type: ignore[arg-type]

        adjacency: dict[UUID, list[AttackPathRelation]] = {}
        for relation in sorted(
            usable,
            key=lambda item: (str(item.source_asset_id), str(item.target_asset_id), str(item.id)),
        ):
            adjacency.setdefault(relation.source_asset_id, []).append(relation)

        paths: list[AttackPath] = []

        def walk(
            current: UUID,
            assets: tuple[UUID, ...],
            relation_chain: tuple[AttackPathRelation, ...],
        ) -> None:
            if len(paths) >= max_paths:
                return
            if len(relation_chain) > max_hops:
                return
            if current in objectives and relation_chain:
                path_findings = tuple(
                    finding
                    for asset_id in assets
                    for finding in sorted(
                        finding_by_asset.get(asset_id, []),
                        key=lambda item: str(item.id),
                    )
                )
                if path_findings:
                    score = max(
                        (risk_scores or {}).get(item.id, 0.0)
                        for item in path_findings
                    )
                    level = _risk_level(score, risk_levels, path_findings)
                    finding_ids = tuple(item.id for item in path_findings)
                    paths.append(
                        AttackPath(
                            asset_ids=assets,
                            relation_ids=tuple(item.id for item in relation_chain),
                            finding_ids=finding_ids,
                            score=round(score, 4),
                            risk_level=level,
                            explanation=(
                                "Path uses only explicitly supplied validated relationships.",
                                (
                                    "Every relationship in the path has at least one evidence reference."
                                ),
                                (
                                    f"Highest associated finding risk is {score:.4f}; "
                                    "no additional exploitability or trust inference was added."
                                ),
                            ),
                        )
                    )
                return

            for relation in adjacency.get(current, []):
                target = relation.target_asset_id
                if target in assets:
                    continue
                walk(target, assets + (target,), relation_chain + (relation,))

        for entry in entries:
            walk(entry, (entry,), ())

        paths.sort(
            key=lambda path: (
                -path.score,
                len(path.relation_ids),
                tuple(str(item) for item in path.asset_ids),
                tuple(str(item) for item in path.relation_ids),
            )
        )
        return AttackPathResult(
            paths=tuple(paths[:max_paths]),
            ignored_relation_ids=tuple(sorted(ignored, key=str)),
        )


def _risk_level(
    score: float,
    risk_levels: dict[UUID, str] | None,
    findings: tuple[Finding, ...],
) -> str:
    if risk_levels:
        levels = [risk_levels[item.id] for item in findings if item.id in risk_levels]
        if levels:
            order = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            return max(levels, key=lambda item: order.get(item, 0))

    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.40:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFORMATIONAL"
