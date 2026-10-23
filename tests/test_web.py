from hashlib import sha256
from threading import Event
from uuid import uuid4

import pytest

from threatlens.domain.models import Campaign, Scope
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.web import (
    HTTPObservation,
    WebAssessmentPolicy,
    WebAssessmentProvider,
    evaluate_web_policy,
)


class MemoryRepository:
    def __init__(self) -> None:
        self.assets = []
        self.evidence = []
        self.findings = []

    def save_asset_for_execution(self, execution_id, asset):
        self.assets.append((execution_id, asset))
        return asset

    def save_evidence(self, evidence):
        self.evidence.append(evidence)

    def save_finding(self, finding):
        self.findings.append(finding)


class FakeProbe:
    def __init__(self, observation: HTTPObservation) -> None:
        self.observation = observation
        self.calls = []

    def request(self, url, method, timeout, max_bytes, *, connect_address):
        self.calls.append((url, method, timeout, max_bytes, connect_address))
        return self.observation


def observation(headers=(), status=200, url="https://example.test/"):
    return HTTPObservation(
        url=url,
        method="HEAD",
        status_code=status,
        reason="OK",
        headers=tuple(headers),
        body_excerpt="",
    )


def test_web_policy_is_deterministic_and_evidence_backed() -> None:
    asset_id = uuid4()
    evidence_id = uuid4()
    findings = evaluate_web_policy(observation(), asset_id, evidence_id)

    assert {finding.vulnerability_id for finding in findings} == {
        "THREATLENS-WEB-HSTS",
        "THREATLENS-WEB-XCTO",
        "THREATLENS-WEB-CSP",
        "THREATLENS-WEB-REFERRER-POLICY",
        "THREATLENS-WEB-FRAME-OPTIONS",
    }
    assert all(finding.evidence_ids == (evidence_id,) for finding in findings)
    assert all(finding.asset_id == asset_id for finding in findings)


def test_web_policy_does_not_flag_hsts_when_present() -> None:
    findings = evaluate_web_policy(
        observation(
            headers=(
                ("strict-transport-security", "max-age=31536000"),
                ("x-content-type-options", "nosniff"),
                ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
                ("referrer-policy", "no-referrer"),
            )
        ),
        uuid4(),
        uuid4(),
    )
    assert findings == ()


def test_web_provider_persists_evidence_and_policy_findings() -> None:
    repository = MemoryRepository()
    from threatlens.domain.models import Asset

    asset = Asset(
        canonical_id="url:https://example.test/", asset_type="url", value="https://example.test/"
    )
    probe = FakeProbe(observation())
    provider = WebAssessmentProvider(
        ProviderHandoff(repository),
        WebAssessmentPolicy(allow_private_addresses=True),
        probe=probe,
        asset_resolver=lambda canonical_id: asset if canonical_id == asset.canonical_id else None,
        destination_resolver=lambda hostname: ("93.184.216.34",),
    )
    campaign = Campaign(
        name="web-assessment",
        scope=Scope(include=("https://example.test/",)),
        authorized=True,
    )

    execution_id = uuid4()
    provider.execute(campaign, execution_id, Event())

    assert len(probe.calls) == 1
    assert probe.calls[0][1] == "HEAD"
    assert probe.calls[0][4] == "93.184.216.34"
    assert len(repository.evidence) == 1
    assert len(repository.findings) == 5
    assert all(
        str(execution_id) == finding_metadata["execution_id"]
        for finding_metadata in [repository.evidence[0].metadata]
    )


def test_web_policy_evaluates_all_session_cookie_headers_without_values():
    response = observation(
        headers=(
            ("set-cookie", "session_id=secret-value; Path=/; HttpOnly; SameSite=Lax"),
            ("set-cookie", "auth_token=another-secret; Secure; SameSite=None"),
        )
    )
    findings = evaluate_web_policy(response, uuid4(), uuid4())
    vulnerability_ids = {finding.vulnerability_id for finding in findings}
    assert "THREATLENS-WEB-COOKIE-SECURE" in vulnerability_ids
    assert "THREATLENS-WEB-COOKIE-HTTPONLY" in vulnerability_ids
    assert "THREATLENS-WEB-COOKIE-SAMESITE-SECURE" not in vulnerability_ids

    serialized = WebAssessmentProvider._serialize(response)
    assert "secret-value" not in serialized
    assert "another-secret" not in serialized
    assert "[REDACTED]" in serialized


def test_web_evidence_keeps_only_safe_headers_and_body_digest():
    body = '<html><input value="private-profile-data"></html>'
    response = HTTPObservation(
        url="https://user:secret-url-value@example.test/profile?session=secret-query-value#private",
        method="GET",
        status_code=200,
        reason="OK",
        headers=(
            ("content-type", "text/html; profile=secret-content-type-value"),
            ("x-api-key", "secret-header-value"),
            ("server", "s" * 513),
            ("location", "https://other.test/?access_token=secret-redirect-value"),
        ),
        body_excerpt=body,
        redirect_location="https://other.test/?access_token=secret-redirect-value",
    )

    serialized = WebAssessmentProvider._serialize(response)

    assert body not in serialized
    assert "private-profile-data" not in serialized
    assert "secret-header-value" not in serialized
    assert "secret-redirect-value" not in serialized
    assert "secret-content-type-value" not in serialized
    assert "secret-url-value" not in serialized
    assert "secret-query-value" not in serialized
    assert "private" not in serialized
    assert "url=https://example.test/profile" in serialized
    assert "x-api-key" not in serialized
    assert "headers_truncated=true" in serialized
    server_line = next(line for line in serialized.splitlines() if line.startswith("server: "))
    assert len(server_line.removeprefix("server: ")) == 512
    assert f"body_excerpt_sha256={sha256(body.encode()).hexdigest()}" in serialized
    assert "redirect_observed=true" in serialized


def test_web_policy_reports_missing_secure_for_samesite_none_cookie():
    response = observation(
        headers=(("set-cookie", "session=secret; SameSite=None; HttpOnly"),),
        url="http://example.test/",
    )
    identifiers = {
        finding.vulnerability_id
        for finding in evaluate_web_policy(response, uuid4(), uuid4())
    }
    assert "THREATLENS-WEB-COOKIE-SECURE" in identifiers
    assert "THREATLENS-WEB-COOKIE-SAMESITE-SECURE" not in identifiers


def test_web_policy_skips_failed_responses_and_respects_frame_ancestors():
    failed = evaluate_web_policy(observation(status=503), uuid4(), uuid4())
    protected = evaluate_web_policy(
        observation(headers=(("content-security-policy", "frame-ancestors 'none'"),)),
        uuid4(),
        uuid4(),
    )
    assert failed == ()
    assert "THREATLENS-WEB-FRAME-OPTIONS" not in {
        finding.vulnerability_id for finding in protected
    }


def test_web_policy_rejects_disabled_or_malformed_security_headers():
    response = observation(
        headers=(
            ("strict-transport-security", "max-age=0"),
            ("x-content-type-options", "invalid"),
            ("content-security-policy", "   "),
            ("referrer-policy", "unknown-policy"),
            ("x-frame-options", "allow-from https://other.test"),
            ("content-security-policy", "x-frame-ancestors 'none'"),
        )
    )
    identifiers = {
        finding.vulnerability_id
        for finding in evaluate_web_policy(response, uuid4(), uuid4())
    }
    assert {
        "THREATLENS-WEB-HSTS",
        "THREATLENS-WEB-XCTO",
        "THREATLENS-WEB-CSP",
        "THREATLENS-WEB-REFERRER-POLICY",
        "THREATLENS-WEB-FRAME-OPTIONS",
    } <= identifiers


def test_web_provider_binds_url_asset_to_execution() -> None:
    repository = MemoryRepository()
    execution_id = uuid4()
    provider = WebAssessmentProvider(
        ProviderHandoff(repository),
        WebAssessmentPolicy(allow_private_addresses=True),
        probe=FakeProbe(observation()),
        destination_resolver=lambda hostname: ("93.184.216.34",),
        repository=repository,
    )
    campaign = Campaign(
        name="web-asset-binding",
        scope=Scope(include=("https://example.test/",)),
        authorized=True,
    )

    provider.execute(campaign, execution_id, Event())

    assert len(repository.assets) == 1
    saved_execution_id, asset = repository.assets[0]
    assert saved_execution_id == execution_id
    assert asset.canonical_id == "url:https://example.test/"
    assert all(finding.asset_id == asset.id for finding in repository.findings)


def test_web_provider_rejects_private_destination_by_default() -> None:
    provider = WebAssessmentProvider(
        ProviderHandoff(MemoryRepository()),
        probe=FakeProbe(observation()),
    )
    campaign = Campaign(
        name="web-ssrf-boundary",
        scope=Scope(include=("http://127.0.0.1/",)),
        authorized=True,
    )
    with pytest.raises(PermissionError, match="non-public"):
        provider.execute(campaign, uuid4(), Event())


def test_web_provider_rejects_empty_dns_answers_before_probe():
    probe = FakeProbe(observation())
    provider = WebAssessmentProvider(
        ProviderHandoff(MemoryRepository()),
        probe=probe,
        destination_resolver=lambda hostname: (),
    )
    campaign = Campaign(
        name="empty-dns",
        scope=Scope(include=("https://example.test/",)),
        authorized=True,
    )
    with pytest.raises(ConnectionError, match="no addresses"):
        provider.execute(campaign, uuid4(), Event())
    assert probe.calls == []


@pytest.mark.parametrize("address", ("224.0.0.1", "0.0.0.0", "ff02::1", "::"))
def test_web_provider_rejects_non_destination_addresses_even_when_private_allowed(address):
    probe = FakeProbe(observation())
    provider = WebAssessmentProvider(
        ProviderHandoff(MemoryRepository()),
        WebAssessmentPolicy(allow_private_addresses=True),
        probe=probe,
        destination_resolver=lambda hostname: (address,),
    )
    campaign = Campaign(
        name="invalid-destination",
        scope=Scope(include=("https://example.test/",)),
        authorized=True,
    )
    with pytest.raises(PermissionError, match="non-public"):
        provider.execute(campaign, uuid4(), Event())
    assert probe.calls == []


def test_pinned_http_connections_use_validated_address_and_hostname_sni(monkeypatch):
    from threatlens.providers.web import _PinnedHTTPConnection, _PinnedHTTPSConnection

    connected = []

    class FakeSocket:
        def close(self):
            pass

    raw_socket = FakeSocket()

    def create_connection(address, timeout, source_address):
        connected.append(address)
        return raw_socket

    monkeypatch.setattr("threatlens.providers.web.socket.create_connection", create_connection)
    http = _PinnedHTTPConnection("example.test", 80, 3.0, "93.184.216.34")
    http.connect()
    assert connected[-1] == ("93.184.216.34", 80)
    http.close()

    https = _PinnedHTTPSConnection("example.test", 443, 3.0, "93.184.216.34")
    assert https._context.check_hostname is True
    assert https._context.verify_mode.value == 2  # ssl.CERT_REQUIRED
    wrapped = FakeSocket()
    sni = []

    class FakeContext:
        def wrap_socket(self, sock, *, server_hostname):
            sni.append(server_hostname)
            return wrapped

    https._context = FakeContext()
    https.connect()
    assert connected[-1] == ("93.184.216.34", 443)
    assert sni == ["example.test"]
    https.close()


def test_socket_http_probe_preserves_authorized_host_and_path(monkeypatch):
    from threatlens.providers import web

    calls = []

    class FakeResponse:
        status = 200
        reason = "OK"

        class headers:
            @staticmethod
            def keys():
                return []

            @staticmethod
            def get_all(key, default):
                return default

        @staticmethod
        def read(max_bytes):
            return b""

        @staticmethod
        def getheader(name):
            return None

    class FakeConnection:
        def __init__(self, host, port, timeout, connect_address):
            calls.append(("connect", host, port, timeout, connect_address))

        def putrequest(self, method, path, *, skip_host):
            calls.append(("request", method, path, skip_host))

        def putheader(self, name, value):
            calls.append(("header", name, value))

        def endheaders(self):
            pass

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(web, "_PinnedHTTPSConnection", FakeConnection)
    response = web.SocketHTTPProbe().request(
        "https://example.test:8443/private?q=1",
        "HEAD",
        3.0,
        1024,
        connect_address="93.184.216.34",
    )
    assert response.status_code == 200
    assert ("connect", "example.test", 8443, 3.0, "93.184.216.34") in calls
    assert ("request", "HEAD", "/private?q=1", True) in calls
    assert ("header", "Host", "example.test:8443") in calls


def test_web_provider_rejects_url_userinfo() -> None:
    with pytest.raises(ValueError, match="userinfo"):
        WebAssessmentProvider._normalize_url("https://user:pass@example.test/")


def test_web_provider_supports_explicit_bounded_get() -> None:
    repository = MemoryRepository()
    probe = FakeProbe(observation())
    provider = WebAssessmentProvider(
        ProviderHandoff(repository),
        WebAssessmentPolicy(methods=("GET",), allow_private_addresses=True),
        probe=probe,
        destination_resolver=lambda hostname: ("93.184.216.34",),
    )
    campaign = Campaign(
        name="bounded-get",
        scope=Scope(include=("https://example.test/",)),
        authorized=True,
    )
    provider.execute(campaign, uuid4(), Event())
    assert probe.calls[0][1] == "GET"

@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (" HTTPS://EXAMPLE.test ", "https://example.test/"),
        ("http://EXAMPLE.test:80", "http://example.test/"),
        ("https://EXAMPLE.test:443/path", "https://example.test/path"),
        ("https://EXAMPLE.test:8443/Path?x=1", "https://example.test:8443/Path?x=1"),
        ("https://[2001:db8::1]:443", "https://[2001:db8::1]/"),
        ("https://BÜCHER.example/", "https://xn--bcher-kva.example/"),
    ),
)
def test_web_provider_normalizes_url_identity(value, expected):
    assert WebAssessmentProvider._normalize_url(value) == expected


@pytest.mark.parametrize(
    "value",
    (
        "https://example.test:invalid/",
        "https://example.test:99999/",
        "ftp://example.test/",
        "https://user:pass@example.test/",
        "https://example.test/#fragment",
    ),
)
def test_web_provider_rejects_invalid_or_unsupported_urls(value):
    with pytest.raises(ValueError):
        WebAssessmentProvider._normalize_url(value)


def test_web_provider_excludes_equivalent_normalized_url():
    repository = MemoryRepository()
    probe = FakeProbe(observation())
    provider = WebAssessmentProvider(
        ProviderHandoff(repository),
        WebAssessmentPolicy(allow_private_addresses=True),
        probe=probe,
        destination_resolver=lambda hostname: ("93.184.216.34",),
    )
    campaign = Campaign(
        name="normalized-exclusion",
        scope=Scope(
            include=("https://EXAMPLE.test",),
            exclude=("https://example.test:443/",),
        ),
        authorized=True,
    )

    provider.execute(campaign, uuid4(), Event())

    assert probe.calls == []
    assert repository.evidence == []
