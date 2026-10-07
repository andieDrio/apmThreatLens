"""Controlled API assessment provider.

Gate 22 provides bounded, read-only HTTP API observation for explicitly scoped
API URL targets. It does not discover endpoints, expand schemas, mutate state,
send credentials, fuzz parameters, or follow redirects.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from threading import Event
from typing import Callable
from uuid import UUID
from urllib.parse import urlparse

from threatlens.domain.models import Asset, Campaign, Evidence, Finding, FindingState, Severity
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.runtime import ProviderMetadata, ProviderCapability
from threatlens.providers.web import HTTPProbe


@dataclass(frozen=True, slots=True)
class APIObservation:
    url: str
    method: str
    status_code: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body_excerpt: str
    redirect_location: str | None = None


@dataclass(frozen=True, slots=True)
class APIAssessmentPolicy:
    methods: tuple[str, ...] = ("HEAD",)
    timeout_seconds: float = 3.0
    max_targets: int = 16
    max_response_bytes: int = 16384
    allow_private_addresses: bool = False
    emit_policy_findings: bool = True

    def __post_init__(self) -> None:
        if not self.methods or any(method not in {"HEAD", "GET"} for method in self.methods):
            raise ValueError("API methods are limited to HEAD and GET")
        if len(set(self.methods)) != len(self.methods):
            raise ValueError("API methods must be unique")
        if not 0.1 <= self.timeout_seconds <= 10.0:
            raise ValueError("API timeout must be within 0.1..10 seconds")
        if not 1 <= self.max_targets <= 16:
            raise ValueError("API max_targets must be within 1..16")
        if not 256 <= self.max_response_bytes <= 16384:
            raise ValueError("API max_response_bytes must be within 256..16384")


class APIAssessmentProvider:
    name = "builtin-api-assessment"
    metadata = ProviderMetadata(
        name=name,
        version="1.0.0",
        capabilities=frozenset({ProviderCapability.WEB, ProviderCapability.EVIDENCE}),
        safe_by_default=True,
    )

    def __init__(
        self,
        handoff: ProviderHandoff,
        policy: APIAssessmentPolicy | None = None,
        probe: HTTPProbe | None = None,
        asset_resolver: Callable[[str], Asset | None] | None = None,
        destination_resolver: Callable[[str], tuple[str, ...]] | None = None,
    ) -> None:
        self.handoff = handoff
        self.policy = policy or APIAssessmentPolicy()
        self.probe = probe
        self.asset_resolver = asset_resolver
        self.destination_resolver = destination_resolver

    def execute(self, campaign: Campaign, execution_id: UUID, cancel_event: Event) -> None:
        if self.probe is None:
            from threatlens.providers.web import SocketHTTPProbe
            self.probe = SocketHTTPProbe()

        targets = [
            self._normalize_url(value)
            for value in campaign.scope.include
            if self._is_url(value)
        ]
        if len(targets) > self.policy.max_targets:
            raise ValueError("API target count exceeds execution policy")
        excluded = {
            self._normalize_url(value)
            for value in campaign.scope.exclude
            if self._is_url(value)
        }

        for url in targets:
            if cancel_event.is_set():
                return
            if url in excluded:
                continue
            self._validate_destination(url)
            for method in self.policy.methods:
                if cancel_event.is_set():
                    return
                observation = self.probe.request(
                    url, method, self.policy.timeout_seconds, self.policy.max_response_bytes
                )
                api_observation = APIObservation(
                    url=observation.url,
                    method=observation.method,
                    status_code=observation.status_code,
                    reason=observation.reason,
                    headers=observation.headers,
                    body_excerpt=observation.body_excerpt,
                    redirect_location=observation.redirect_location,
                )
                evidence = Evidence(
                    kind="api-assessment",
                    content=self._serialize(api_observation),
                    source=self.name,
                    metadata={
                        "url": url,
                        "method": method,
                        "status_code": str(observation.status_code),
                        "content_type": self._header(observation, "content-type"),
                        "location": observation.redirect_location or "",
                    },
                )
                persisted = self.handoff.persist_evidence(
                    execution_id, self.metadata, evidence
                )
                if self.policy.emit_policy_findings and self.asset_resolver is not None:
                    asset = self.asset_resolver(f"url:{url}")
                    if asset is None:
                        raise ValueError(f"API target has no authorized asset: {url}")
                    for finding in evaluate_api_policy(
                        api_observation, asset.id, persisted.id
                    ):
                        self.handoff.persist_finding(
                            execution_id, self.metadata, asset, finding, (persisted,)
                        )

    def _validate_destination(self, url: str) -> None:
        hostname = urlparse(url).hostname
        if not hostname:
            raise ValueError("API assessment URL has no hostname")
        try:
            addresses = {ipaddress.ip_address(hostname)}
        except ValueError:
            if self.destination_resolver is None:
                from threatlens.providers.web import WebAssessmentProvider
                addresses = set(
                    ipaddress.ip_address(address)
                    for address in WebAssessmentProvider._resolve_addresses(hostname)
                )
            else:
                addresses = {
                    ipaddress.ip_address(address)
                    for address in self.destination_resolver(hostname)
                }
        if not self.policy.allow_private_addresses and any(
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            for address in addresses
        ):
            raise PermissionError("API assessment destination resolves to a non-public address")

    @staticmethod
    def _is_url(value: str) -> bool:
        return "://" in value

    @staticmethod
    def _normalize_url(value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"API assessment requires an absolute HTTP(S) URL: {value!r}")
        if parsed.username or parsed.password:
            raise ValueError("API assessment URLs cannot contain userinfo")
        if parsed.fragment:
            raise ValueError("API assessment URLs cannot contain fragments")
        return value.strip()

    @staticmethod
    def _header(observation: APIObservation | object, name: str) -> str:
        wanted = name.lower()
        return next(
            (value for key, value in getattr(observation, "headers") if key.lower() == wanted),
            "",
        )

    @staticmethod
    def _serialize(observation: APIObservation) -> str:
        headers = "\n".join(f"{key}: {value}" for key, value in observation.headers)
        return (
            f"url={observation.url}\nmethod={observation.method}\n"
            f"status_code={observation.status_code}\nreason={observation.reason}\n"
            f"headers:\n{headers}\nredirect_location={observation.redirect_location or ''}\n"
            f"body_excerpt:\n{observation.body_excerpt}"
        )


def evaluate_api_policy(
    observation: APIObservation,
    asset_id: UUID,
    evidence_id: UUID,
) -> tuple[Finding, ...]:
    """Deterministic API policy checks; performs no network access."""
    content_type = next(
        (
            value.split(";", 1)[0].strip().lower()
            for key, value in observation.headers
            if key.lower() == "content-type"
        ),
        "",
    )
    if observation.status_code < 400 and content_type == "application/json":
        if observation.method == "HEAD" or not observation.body_excerpt.strip():
            return ()
        import json
        try:
            json.loads(observation.body_excerpt)
        except json.JSONDecodeError:
            return (
                Finding(
                    title="Malformed JSON API Response",
                    asset_id=asset_id,
                    evidence_ids=(evidence_id,),
                    state=FindingState.SUSPECTED,
                    severity=Severity.LOW,
                    vulnerability_id="THREATLENS-API-JSON",
                    cwe="CWE-20",
                    confidence=0.90,
                    source=APIAssessmentProvider.name,
                ),
            )
    return ()
