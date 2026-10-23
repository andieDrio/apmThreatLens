"""Conservative parser for NVD CVE API 2.0 responses.

Only explicit, vulnerable CPE 2.3 entries with one exact version are emitted.
Version ranges and compound applicability expressions are intentionally not
flattened into exact-version matches.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from threatlens.providers.vulnerability_intelligence import (
    VulnerabilityIntelligenceRecord,
    normalize_vulnerability_record,
)

_SOURCE = "NVD CVE API 2.0"
_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _cpe_components(criteria: object) -> tuple[str, str, str] | None:
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None
    components: list[str] = []
    value: list[str] = []
    escaped = False
    for character in criteria:
        if character == ":" and not escaped:
            components.append("".join(value))
            value.clear()
            continue
        value.append(character)
        if character == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
    components.append("".join(value))
    if len(components) != 13 or components[:2] != ["cpe", "2.3"]:
        return None
    vendor = components[3].replace("\\", "").strip()
    product = components[4].replace("\\", "").strip()
    version = components[5].replace("\\", "").strip()
    if (
        vendor.casefold() in {"", "*", "-", "?"}
        or not product
        or version.casefold() in {"", "*", "-", "?"}
    ):
        return None
    return vendor, product, version


def _exact_affected_products(cve: Mapping[str, Any]) -> dict[tuple[str, str], set[str]]:
    affected: dict[tuple[str, str], set[str]] = defaultdict(set)

    def visit_nodes(nodes: object) -> None:
        if not isinstance(nodes, list):
            return
        for node in nodes:
            if not isinstance(node, Mapping):
                continue
            if node.get("operator", "OR") != "OR" or node.get("negate") is True:
                continue
            matches = node.get("cpeMatch")
            if isinstance(matches, list):
                for match in matches:
                    if not isinstance(match, Mapping) or match.get("vulnerable") is not True:
                        continue
                    if any(
                        key in match
                        for key in (
                            "versionStartIncluding",
                            "versionStartExcluding",
                            "versionEndIncluding",
                            "versionEndExcluding",
                        )
                    ):
                        continue
                    parsed = _cpe_components(match.get("criteria"))
                    if parsed is None:
                        continue
                    vendor, product, version = parsed
                    affected[(vendor, product)].add(version)
            visit_nodes(node.get("nodes"))

    configurations = cve.get("configurations")
    if isinstance(configurations, list):
        for configuration in configurations:
            if isinstance(configuration, Mapping):
                visit_nodes(configuration.get("nodes"))
    return affected


def _description(cve: Mapping[str, Any], cve_id: str) -> str:
    descriptions = cve.get("descriptions")
    if isinstance(descriptions, list):
        for description in descriptions:
            if (
                isinstance(description, Mapping)
                and description.get("lang") == "en"
                and isinstance(description.get("value"), str)
                and description["value"].strip()
            ):
                return description["value"].strip()
    return f"NVD vulnerability {cve_id}"


def _weakness(cve: Mapping[str, Any]) -> str | None:
    weaknesses = cve.get("weaknesses")
    if not isinstance(weaknesses, list):
        return None
    for weakness in weaknesses:
        descriptions = weakness.get("description") if isinstance(weakness, Mapping) else None
        if not isinstance(descriptions, list):
            continue
        for item in descriptions:
            value = item.get("value") if isinstance(item, Mapping) else None
            if isinstance(value, str) and value.startswith("CWE-") and value != "CWE-NVD-noinfo":
                return value
    return None


def _cvss(cve: Mapping[str, Any]) -> tuple[float | None, str]:
    metrics = cve.get("metrics")
    if not isinstance(metrics, Mapping):
        return None, "INFORMATIONAL"
    for key in _METRIC_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            data = entry.get("cvssData") if isinstance(entry, Mapping) else None
            if not isinstance(data, Mapping):
                continue
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entry.get("baseSeverity")
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                if isinstance(severity, str) and severity.upper() in {
                    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
                }:
                    return float(score), severity.upper()
    return None, "INFORMATIONAL"


def parse_nvd_cve_response(
    payload: Mapping[str, Any],
) -> tuple[VulnerabilityIntelligenceRecord, ...]:
    """Parse exact-version records from a validated NVD CVE API 2.0 payload.

    This function does not fetch data or validate transport authenticity. The
    caller must obtain the payload from the official HTTPS endpoint and apply
    normal response-size, timeout, and rate limits.
    """

    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("NVD response is missing the vulnerabilities list")
    records: list[VulnerabilityIntelligenceRecord] = []
    for item in vulnerabilities:
        cve = item.get("cve") if isinstance(item, Mapping) else None
        if not isinstance(cve, Mapping):
            continue
        cve_id = cve.get("id")
        if not isinstance(cve_id, str):
            continue
        vuln_status = cve.get("vulnStatus")
        if isinstance(vuln_status, str) and vuln_status.casefold() == "rejected":
            continue
        affected = _exact_affected_products(cve)
        if not affected:
            continue
        cvss, severity = _cvss(cve)
        references_data = cve.get("references")
        references = tuple(
            reference["url"]
            for reference in references_data
            if isinstance(reference, Mapping)
            and isinstance(reference.get("url"), str)
            and reference["url"].startswith(("https://", "http://"))
        ) if isinstance(references_data, list) else ()
        for (vendor, product), versions in sorted(
            affected.items(), key=lambda row: (row[0][0].casefold(), row[0][1].casefold())
        ):
            records.append(
                normalize_vulnerability_record(
                    vulnerability_id=cve_id,
                    title=_description(cve, cve_id),
                    severity=severity,
                    cve=cve_id,
                    cwe=_weakness(cve),
                    vendor=vendor,
                    product=product,
                    affected_versions=tuple(sorted(versions)),
                    cvss=cvss,
                    confidence=0.95,
                    references=references,
                    source=_SOURCE,
                )
            )
    return tuple(records)
