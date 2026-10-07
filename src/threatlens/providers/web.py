"""Controlled web/API HTTP assessment provider.

Gate 21 provides bounded, evidence-first HTTP observation and conservative
web security-policy findings for explicitly scoped URL targets. It never
follows redirects, executes arbitrary methods, or expands scope from
responses.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from threading import Event
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID
from urllib.parse import urlparse

from threatlens.domain.models import Asset, Campaign, Evidence, Finding, FindingState, Severity
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata


@dataclass(frozen=True, slots=True)
class HTTPObservation:
    url: str
    method: str
    status_code: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body_excerpt: str
    redirect_location: str | None = None


class HTTPProbe(Protocol):
    def request(self, url: str, method: str, timeout: float, max_bytes: int) -> HTTPObservation: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class SocketHTTPProbe:
    """Bounded HTTP client with redirect following disabled."""

    def request(self, url: str, method: str, timeout: float, max_bytes: int) -> HTTPObservation:
        request = Request(url, method=method, headers={"User-Agent": "APM-ThreatLens/1.0"})
        opener = build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=timeout) as response:
                body = response.read(max_bytes).decode("utf-8", errors="replace")
                headers = tuple((key.lower(), value) for key, value in response.headers.items())
                return HTTPObservation(
                    url=url,
                    method=method,
                    status_code=response.status,
                    reason=response.reason or "",
                    headers=headers,
                    body_excerpt=body,
                )
        except HTTPError as exc:
            body = exc.read(max_bytes).decode("utf-8", errors="replace")
            headers = tuple((key.lower(), value) for key, value in exc.headers.items())
            return HTTPObservation(
                url=url,
                method=method,
                status_code=exc.code,
                reason=exc.reason or "",
                headers=headers,
                body_excerpt=body,
                redirect_location=exc.headers.get("Location") if exc.code in {301, 302, 303, 307, 308} else None,
            )
        except (URLError, OSError, TimeoutError) as exc:
            raise ConnectionError(f"HTTP assessment failed: {type(exc).__name__}: {exc}") from exc


@dataclass(frozen=True, slots=True)
class WebAssessmentPolicy:
    methods: tuple[str, ...] = ("HEAD",)
    timeout_seconds: float = 3.0
    max_targets: int = 16
    max_response_bytes: int = 16384
    allow_private_addresses: bool = False
    emit_policy_findings: bool = True

    def __post_init__(self) -> None:
        allowed = {"HEAD", "GET"}
        if not self.methods or any(method not in allowed for method in self.methods):
            raise ValueError("web methods are limited to HEAD and GET")
        if len(set(self.methods)) != len(self.methods):
            raise ValueError("web methods must be unique")
        if not 0.1 <= self.timeout_seconds <= 10.0:
            raise ValueError("web timeout must be within 0.1..10 seconds")
        if not 1 <= self.max_targets <= 16:
            raise ValueError("web max_targets must be within 1..16")
        if not 256 <= self.max_response_bytes <= 16384:
            raise ValueError("web max_response_bytes must be within 256..16384")


class WebAssessmentProvider:
    name = "builtin-web-assessment"
    metadata = ProviderMetadata(
        name=name,
        version="1.0.0",
        capabilities=frozenset({ProviderCapability.WEB, ProviderCapability.EVIDENCE}),
        safe_by_default=True,
    )

    def __init__(
        self,
        handoff: ProviderHandoff,
        policy: WebAssessmentPolicy | None = None,
        probe: HTTPProbe | None = None,
        asset_resolver=None,
    ) -> None:
        self.handoff = handoff
        self.policy = policy or WebAssessmentPolicy()
        self.probe = probe or SocketHTTPProbe()
        self.asset_resolver = asset_resolver

    def execute(self, campaign: Campaign, execution_id: UUID, cancel_event: Event) -> None:
        targets = [self._normalize_url(value) for value in campaign.scope.include if self._is_url(value)]
        if len(targets) > self.policy.max_targets:
            raise ValueError("web target count exceeds execution policy")
        excluded = {self._normalize_url(value) for value in campaign.scope.exclude if self._is_url(value)}
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
                evidence = Evidence(
                    kind="http-assessment",
                    content=self._serialize(observation),
                    source=self.name,
                    metadata={
                        "url": url,
                        "method": method,
                        "status_code": str(observation.status_code),
                        "content_type": self._header(observation, "content-type"),
                        "location": observation.redirect_location or "",
                    },
                )
                persisted = self.handoff.persist_evidence(execution_id, self.metadata, evidence)
                if self.policy.emit_policy_findings and self.asset_resolver is not None:
                    asset = self.asset_resolver(f"url:{url}")
                    if asset is not None:
                        for finding in evaluate_web_policy(observation, asset.id, persisted.id):
                            self.handoff.persist_finding(
                                execution_id, self.metadata, asset, finding, (persisted,)
                            )

    @staticmethod
    def _is_url(value: str) -> bool:
        return "://" in value

    @staticmethod
    def _normalize_url(value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"web assessment requires an absolute HTTP(S) URL: {value!r}")
        if parsed.username or parsed.password:
            raise ValueError("web assessment URLs cannot contain userinfo")
        if parsed.fragment:
            raise ValueError("web assessment URLs cannot contain fragments")
        return value.strip()

    def _validate_destination(self, url: str) -> None:
        hostname = urlparse(url).hostname
        if not hostname:
            raise ValueError("web assessment URL has no hostname")
        try:
            addresses = {ipaddress.ip_address(hostname)}
        except ValueError:
            try:
                addresses = {
                    ipaddress.ip_address(info[4][0])
                    for info in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
                }
            except OSError as exc:
                raise ConnectionError(f"web assessment DNS resolution failed: {hostname}") from exc
        if not self.policy.allow_private_addresses and any(
            address.is_private or address.is_loopback or address.is_link_local or address.is_reserved
            for address in addresses
        ):
            raise PermissionError("web assessment destination resolves to a non-public address")

    @staticmethod
    def _header(observation: HTTPObservation, name: str) -> str:
        wanted = name.lower()
        return next((value for key, value in observation.headers if key == wanted), "")

    @staticmethod
    def _serialize(observation: HTTPObservation) -> str:
        headers = "\n".join(f"{key}: {value}" for key, value in observation.headers)
        return (
            f"url={observation.url}\nmethod={observation.method}\n"
            f"status_code={observation.status_code}\nreason={observation.reason}\n"
            f"headers:\n{headers}\nredirect_location={observation.redirect_location or ''}\n"
            f"body_excerpt:\n{observation.body_excerpt}"
        )


def evaluate_web_policy(
    observation: HTTPObservation,
    asset_id: UUID,
    evidence_id: UUID,
) -> tuple[Finding, ...]:
    """Deterministic, evidence-backed policy checks; no network access."""
    headers = {key.lower(): value for key, value in observation.headers}
    findings: list[Finding] = []
    if observation.status_code < 400 and observation.url.lower().startswith("https://"):
        if "strict-transport-security" not in headers:
            findings.append(
                Finding(
                    title="Missing HTTP Strict Transport Security",
                    asset_id=asset_id,
                    evidence_ids=(evidence_id,),
                    state=FindingState.LIKELY,
                    severity=Severity.MEDIUM,
                    vulnerability_id="THREATLENS-WEB-HSTS",
                    cwe="CWE-319",
                    confidence=0.85,
                    source=WebAssessmentProvider.name,
                )
            )
    if observation.status_code < 400 and "x-content-type-options" not in headers:
        findings.append(
            Finding(
                title="Missing X-Content-Type-Options Header",
                asset_id=asset_id,
                evidence_ids=(evidence_id,),
                state=FindingState.SUSPECTED,
                severity=Severity.LOW,
                vulnerability_id="THREATLENS-WEB-XCTO",
                cwe="CWE-693",
                confidence=0.75,
                source=WebAssessmentProvider.name,
            )
        )
    return tuple(findings)
