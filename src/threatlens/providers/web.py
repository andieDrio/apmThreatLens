"""Controlled web/API HTTP assessment provider.

Gate 21 provides bounded, evidence-first HTTP observation and conservative
web security-policy findings for explicitly scoped URL targets. It never
follows redirects, executes arbitrary methods, or expands scope from
responses.
"""

from __future__ import annotations

import ipaddress
import http.client
import ssl
import socket
from dataclasses import dataclass
from threading import Event
from typing import Protocol
from uuid import UUID
from urllib.parse import urlparse, urlsplit

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
    def request(
        self, url: str, method: str, timeout: float, max_bytes: int, *, connect_address: str
    ) -> HTTPObservation: ...


class SocketHTTPProbe:
    """Bounded HTTP client pinned to a previously validated DNS address."""

    def request(
        self,
        url: str,
        method: str,
        timeout: float,
        max_bytes: int,
        *,
        connect_address: str,
    ) -> HTTPObservation:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("HTTP probe requires an absolute HTTP(S) URL")
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        request_path = parsed.path or "/"
        if parsed.query:
            request_path += f"?{parsed.query}"
        host_header = parsed.hostname
        if ":" in host_header:
            host_header = f"[{host_header}]"
        else:
            host_header = host_header.encode("idna").decode("ascii")
        if parsed.port is not None:
            host_header += f":{parsed.port}"
        connection_type = (
            _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
        )
        connection = connection_type(parsed.hostname, port, timeout, connect_address)
        try:
            connection.putrequest(method, request_path, skip_host=True)
            connection.putheader("Host", host_header)
            connection.putheader("User-Agent", "APM-ThreatLens/1.0")
            connection.endheaders()
            response = connection.getresponse()
            body = response.read(max_bytes).decode("utf-8", errors="replace")
            headers = tuple(
                (key.lower(), value)
                for key in response.headers.keys()
                for value in response.headers.get_all(key, [])
            )
            return HTTPObservation(
                url=url,
                method=method,
                status_code=response.status,
                reason=response.reason or "",
                headers=headers,
                body_excerpt=body,
                redirect_location=response.getheader("Location")
                if response.status in {301, 302, 303, 307, 308}
                else None,
            )
        except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as exc:
            raise ConnectionError(f"HTTP assessment failed: {type(exc).__name__}: {exc}") from exc
        finally:
            connection.close()


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, timeout: float, connect_address: str) -> None:
        super().__init__(host, port, timeout=timeout)
        self._connect_address = connect_address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._connect_address, self.port), self.timeout, self.source_address
        )


class _PinnedHTTPSConnection(_PinnedHTTPConnection):
    def __init__(self, host: str, port: int, timeout: float, connect_address: str) -> None:
        super().__init__(host, port, timeout, connect_address)
        self._context = ssl.create_default_context()

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._connect_address, self.port), self.timeout, self.source_address
        )
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except BaseException:
            raw_socket.close()
            raise


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
        destination_resolver=None,
        repository=None,
    ) -> None:
        self.handoff = handoff
        self.policy = policy or WebAssessmentPolicy()
        self.probe = probe or SocketHTTPProbe()
        self.asset_resolver = asset_resolver
        self.destination_resolver = destination_resolver or self._resolve_addresses
        self.repository = repository

    def execute(self, campaign: Campaign, execution_id: UUID, cancel_event: Event) -> None:
        targets = [self._normalize_url(value) for value in campaign.scope.include]
        if len(targets) > self.policy.max_targets:
            raise ValueError("web target count exceeds execution policy")
        excluded = {
            self._normalize_url(value) for value in campaign.scope.exclude if self._is_url(value)
        }
        for url in targets:
            if cancel_event.is_set():
                return
            if url in excluded:
                continue
            connect_address = self._validate_destination(url)
            asset = self._ensure_asset(execution_id, url)
            for method in self.policy.methods:
                if cancel_event.is_set():
                    return
                observation = self.probe.request(
                    url,
                    method,
                    self.policy.timeout_seconds,
                    self.policy.max_response_bytes,
                    connect_address=connect_address,
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
                if self.policy.emit_policy_findings:
                    if asset is not None:
                        resolved_asset = asset
                    elif self.asset_resolver is not None:
                        resolved_asset = self.asset_resolver(f"url:{url}")
                    else:
                        resolved_asset = None
                    if resolved_asset is not None:
                        for finding in evaluate_web_policy(
                            observation, resolved_asset.id, persisted.id
                        ):
                            self.handoff.persist_finding(
                                execution_id, self.metadata, resolved_asset, finding, (persisted,)
                            )

    def _ensure_asset(self, execution_id: UUID, url: str) -> Asset | None:
        if self.repository is None:
            return None
        asset = Asset(canonical_id=f"url:{url}", asset_type="url", value=url)
        save_for_execution = getattr(self.repository, "save_asset_for_execution", None)
        if callable(save_for_execution):
            return save_for_execution(execution_id, asset)
        if getattr(self.repository, "requires_execution_fence", False):
            raise RuntimeError("repository requires execution-fenced asset persistence")
        self.repository.save_asset(asset)
        return asset

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

    def _validate_destination(self, url: str) -> str:
        hostname = urlparse(url).hostname
        if not hostname:
            raise ValueError("web assessment URL has no hostname")
        try:
            addresses = {ipaddress.ip_address(hostname)}
        except ValueError:
            try:
                addresses = {
                    ipaddress.ip_address(address) for address in self.destination_resolver(hostname)
                }
            except OSError as exc:
                raise ConnectionError(f"web assessment DNS resolution failed: {hostname}") from exc
        if not addresses:
            raise ConnectionError(
                f"web assessment DNS resolution returned no addresses: {hostname}"
            )
        if len(addresses) > 16:
            raise ValueError("web assessment DNS answer count exceeds execution policy")
        if any(
            address.is_multicast
            or address.is_unspecified
            or (not self.policy.allow_private_addresses and not address.is_global)
            for address in addresses
        ):
            raise PermissionError("web assessment destination resolves to a non-public address")
        return str(sorted(addresses, key=lambda address: (address.version, int(address)))[0])

    @staticmethod
    def _resolve_addresses(hostname: str) -> tuple[str, ...]:
        try:
            return tuple(
                info[4][0] for info in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            )
        except OSError as exc:
            raise ConnectionError(f"web assessment DNS resolution failed: {hostname}") from exc

    @staticmethod
    def _header(observation: HTTPObservation, name: str) -> str:
        wanted = name.lower()
        return next((value for key, value in observation.headers if key == wanted), "")

    @staticmethod
    def _serialize(observation: HTTPObservation) -> str:
        headers = "\n".join(
            f"{key}: {_redact_set_cookie(value) if key.lower() == 'set-cookie' else value}"
            for key, value in observation.headers
        )
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
    csp_values = tuple(
        value for key, value in observation.headers if key.lower() == "content-security-policy"
    )
    findings: list[Finding] = []
    if observation.status_code >= 400:
        return ()

    if observation.url.lower().startswith("https://"):
        if not _valid_hsts(headers.get("strict-transport-security", "")):
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
    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
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

    if not any(_valid_csp(value) for value in csp_values):
        findings.append(
            _posture_finding(
                "Content Security Policy header is missing",
                "THREATLENS-WEB-CSP",
                "CWE-693",
                asset_id,
                evidence_id,
            )
        )

    if not _valid_referrer_policy(headers.get("referrer-policy", "")):
        findings.append(
            _posture_finding(
                "Referrer Policy header is missing",
                "THREATLENS-WEB-REFERRER-POLICY",
                "CWE-200",
                asset_id,
                evidence_id,
            )
        )

    if not _valid_frame_options(headers.get("x-frame-options", "")) and not any(
        _csp_has_frame_ancestors(value) for value in csp_values
    ):
        findings.append(
            _posture_finding(
                "Clickjacking protection header is missing",
                "THREATLENS-WEB-FRAME-OPTIONS",
                "CWE-1021",
                asset_id,
                evidence_id,
            )
        )

    session_cookies = _session_cookie_attributes(observation)
    if any("secure" not in attributes for attributes in session_cookies):
        findings.append(
            _posture_finding(
                "Session cookie is missing the Secure attribute",
                "THREATLENS-WEB-COOKIE-SECURE",
                "CWE-614",
                asset_id,
                evidence_id,
            )
        )
    if any("httponly" not in attributes for attributes in session_cookies):
        findings.append(
            _posture_finding(
                "Session cookie is missing the HttpOnly attribute",
                "THREATLENS-WEB-COOKIE-HTTPONLY",
                "CWE-1004",
                asset_id,
                evidence_id,
            )
        )
    if any(
        attributes.get("samesite") not in {"lax", "strict", "none"}
        for attributes in session_cookies
    ):
        findings.append(
            _posture_finding(
                "Session cookie is missing the SameSite attribute",
                "THREATLENS-WEB-COOKIE-SAMESITE",
                "CWE-1275",
                asset_id,
                evidence_id,
            )
        )
    return tuple(findings)


def _valid_hsts(value: str) -> bool:
    for directive in value.split(";"):
        name, separator, raw_value = directive.strip().partition("=")
        normalized_value = raw_value.strip()
        if (
            name.lower() == "max-age"
            and separator
            and normalized_value.isdigit()
            and len(normalized_value) <= 10
        ):
            return int(normalized_value) > 0
    return False


def _valid_referrer_policy(value: str) -> bool:
    valid = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
    policies = [part.strip().lower() for part in value.split(",") if part.strip()]
    return bool(policies) and policies[-1] in valid


def _valid_frame_options(value: str) -> bool:
    return value.strip().lower() in {"deny", "sameorigin"}


def _valid_csp(value: str) -> bool:
    known_directives = {
        "base-uri",
        "block-all-mixed-content",
        "child-src",
        "connect-src",
        "default-src",
        "font-src",
        "form-action",
        "frame-ancestors",
        "frame-src",
        "img-src",
        "manifest-src",
        "media-src",
        "navigate-to",
        "object-src",
        "plugin-types",
        "report-to",
        "report-uri",
        "require-trusted-types-for",
        "sandbox",
        "script-src",
        "script-src-attr",
        "script-src-elem",
        "style-src",
        "style-src-attr",
        "style-src-elem",
        "trusted-types",
        "upgrade-insecure-requests",
        "worker-src",
    }
    for directive in value.split(";"):
        parts = directive.strip().split(maxsplit=1)
        if not parts or parts[0].lower() not in known_directives:
            continue
        if len(parts) > 1 or parts[0].lower() in {
            "block-all-mixed-content",
            "upgrade-insecure-requests",
        }:
            return True
    return False


def _csp_has_frame_ancestors(value: str) -> bool:
    return any(
        len(parts := directive.strip().split(maxsplit=1)) > 1
        and parts[0].lower() == "frame-ancestors"
        for directive in value.split(";")
    )


def _session_cookie_attributes(observation: HTTPObservation) -> tuple[dict[str, str | None], ...]:
    """Extract only attributes from session-like cookies; never retain their values."""
    cookies = []
    for key, value in observation.headers:
        if key.lower() != "set-cookie":
            continue
        segments = [segment.strip() for segment in value.split(";")]
        cookie_name = segments[0].partition("=")[0].strip().lower()
        if not cookie_name or not any(
            marker in cookie_name for marker in ("session", "auth", "jwt")
        ) and cookie_name not in {"sid", "jsessionid", "phpsessid"} and not cookie_name.endswith(
            ("_sid", "-sid")
        ):
            continue
        attributes: dict[str, str | None] = {}
        for segment in segments[1:]:
            name, separator, attribute_value = segment.partition("=")
            attributes[name.strip().lower()] = (
                attribute_value.strip().lower() if separator else None
            )
        cookies.append(attributes)
    return tuple(cookies)


def _redact_set_cookie(value: str) -> str:
    """Remove cookie names and values while retaining safe security attributes."""
    segments = [segment.strip() for segment in value.split(";")]
    safe_attributes = []
    for segment in segments[1:]:
        name, separator, attribute_value = segment.partition("=")
        normalized_name = name.strip().lower()
        if normalized_name in {"secure", "httponly"}:
            safe_attributes.append(normalized_name.capitalize())
        elif normalized_name == "samesite" and separator:
            same_site = attribute_value.strip().lower()
            if same_site in {"strict", "lax", "none"}:
                safe_attributes.append(f"SameSite={same_site.capitalize()}")
            else:
                safe_attributes.append("SameSite=[REDACTED]")
        elif normalized_name in {"path", "domain", "expires", "max-age"}:
            safe_attributes.append(f"{name.strip()}=[REDACTED]")
    suffix = "; ".join(safe_attributes)
    return "[REDACTED]" + (f"; {suffix}" if suffix else "")


def _posture_finding(
    title: str,
    vulnerability_id: str,
    cwe: str,
    asset_id: UUID,
    evidence_id: UUID,
) -> Finding:
    return Finding(
        title=title,
        asset_id=asset_id,
        evidence_ids=(evidence_id,),
        state=FindingState.SUSPECTED,
        severity=Severity.LOW,
        vulnerability_id=vulnerability_id,
        cwe=cwe,
        confidence=0.78,
        source=WebAssessmentProvider.name,
    )
