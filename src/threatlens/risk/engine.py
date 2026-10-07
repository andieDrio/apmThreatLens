"""Deterministic explainable risk scoring for correlated findings.

The engine is deliberately network-free. It consumes a normalized Finding and
explicit environmental context supplied by the assessment/orchestration layer.
Missing environmental inputs are excluded from the weighted calculation rather
than guessed, so the result remains auditable and evidence-backed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from threatlens.domain.models import Finding, Severity


class RiskLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass(frozen=True, slots=True)
class RiskContext:
    """Explicit environmental inputs, all normalized to 0..1.

    None means unknown, not zero. Unknown factors are omitted from the weighted
    calculation so missing telemetry or business context is never interpreted
    as evidence of low risk.
    """

    exploitability: float | None = None
    exposure: float | None = None
    asset_criticality: float | None = None
    business_impact: float | None = None
    threat_relevance: float | None = None
    control_coverage: float | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        supplied_context = any(
            getattr(self, name) is not None
            for name in (
                "exploitability",
                "exposure",
                "asset_criticality",
                "business_impact",
                "threat_relevance",
                "control_coverage",
            )
        )
        if supplied_context and (self.source is None or not self.source.strip()):
            raise ValueError("risk context source is required when context is supplied")
        if self.source is not None and not self.source.strip():
            raise ValueError("risk context source cannot be blank")
        for name in (
            "exploitability",
            "exposure",
            "asset_criticality",
            "business_impact",
            "threat_relevance",
            "control_coverage",
        ):
            value = getattr(self, name)
            if value is not None and not 0.0 <= value <= 1.0:
                raise ValueError(f"risk context {name} must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class RiskFactor:
    name: str
    score: float
    weight: float
    rationale: str
    source: str

    @property
    def contribution(self) -> float:
        return self.score * self.weight


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    finding_id: str
    level: RiskLevel
    score: float
    factors: tuple[RiskFactor, ...]
    explanation: tuple[str, ...]
    inputs_used: tuple[str, ...]
    missing_inputs: tuple[str, ...]
    context_source: str | None = None


class RiskEngine:
    """Compute deterministic, explainable risk for an already-normalized finding."""

    _WEIGHTS = {
        "technical_severity": 0.20,
        "exploitability": 0.15,
        "exposure": 0.15,
        "asset_criticality": 0.15,
        "business_impact": 0.15,
        "threat_relevance": 0.10,
        "confidence": 0.10,
    }

    def assess(self, finding: Finding, context: RiskContext | None = None) -> RiskAssessment:
        context = context or RiskContext()
        values: dict[str, tuple[float, str, str]] = {}

        values["technical_severity"] = (
            _severity_score(finding.severity),
            f"Finding severity is {finding.severity.value}.",
            "Finding.severity",
        )
        values["confidence"] = (
            finding.confidence,
            f"Finding confidence is {finding.confidence:.2f}.",
            "Finding.confidence",
        )

        if context.exploitability is not None:
            values["exploitability"] = (
                context.exploitability,
                _band_rationale("Exploitability", context.exploitability),
                "RiskContext.exploitability",
            )
        elif finding.cvss is not None:
            derived = finding.cvss / 10.0
            values["exploitability"] = (
                derived,
                (
                    f"Exploitability is derived from supplied CVSS {finding.cvss:.1f}; "
                    "CVSS is not used as the sole risk determinant."
                ),
                "Finding.cvss",
            )

        for name, label in (
            ("exposure", "Exposure"),
            ("asset_criticality", "Asset criticality"),
            ("business_impact", "Business impact"),
            ("threat_relevance", "Threat relevance"),
        ):
            value = getattr(context, name)
            if value is not None:
                values[name] = (value, _band_rationale(label, value), f"RiskContext.{name}")

        factors = tuple(
            RiskFactor(
                name=name,
                score=score,
                weight=self._WEIGHTS[name],
                rationale=rationale,
                source=source,
            )
            for name, (score, rationale, source) in values.items()
        )

        available_weight = sum(self._WEIGHTS[name] for name in values)
        weighted = sum(factor.contribution for factor in factors)
        base_score = weighted / available_weight if available_weight else 0.0

        if context.control_coverage is not None:
            mitigation = 0.50 * context.control_coverage
            score = base_score * (1.0 - mitigation)
            explanation = [factor.rationale for factor in factors]
            explanation.append(
                (
                    f"Control coverage is {context.control_coverage:.2f}; "
                    f"residual risk is reduced by {mitigation * 100:.1f}%."
                )
            )
        else:
            score = base_score
            explanation = [factor.rationale for factor in factors]
            explanation.append(
                "Control coverage is unknown and therefore does not reduce the score."
            )

        score = round(max(0.0, min(1.0, score)), 4)
        level = _risk_level(score)
        missing = tuple(
            name
            for name in (
                "exploitability",
                "exposure",
                "asset_criticality",
                "business_impact",
                "threat_relevance",
            )
            if name not in values
        )
        if context.control_coverage is None:
            missing = missing + ("control_coverage",)

        return RiskAssessment(
            finding_id=str(finding.id),
            level=level,
            score=score,
            factors=factors,
            explanation=tuple(explanation),
            inputs_used=tuple(factor.source for factor in factors),
            missing_inputs=missing,
            context_source=context.source,
        )


def _severity_score(severity: Severity) -> float:
    return {
        Severity.INFORMATIONAL: 0.0,
        Severity.LOW: 0.25,
        Severity.MEDIUM: 0.50,
        Severity.HIGH: 0.75,
        Severity.CRITICAL: 1.0,
    }[severity]


def _band_rationale(label: str, value: float) -> str:
    band = "low" if value < 0.34 else "moderate" if value < 0.67 else "high"
    return f"{label} is {band} ({value:.2f})."


def _risk_level(score: float) -> RiskLevel:
    if score >= 0.85:
        return RiskLevel.CRITICAL
    if score >= 0.65:
        return RiskLevel.HIGH
    if score >= 0.40:
        return RiskLevel.MEDIUM
    if score > 0.0:
        return RiskLevel.LOW
    return RiskLevel.INFORMATIONAL
