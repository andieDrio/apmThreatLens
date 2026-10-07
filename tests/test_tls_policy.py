from datetime import datetime, UTC
from uuid import uuid4

from threatlens.providers.tls import TLSObservation
from threatlens.providers.tls_policy import evaluate_tls_observation


def _obs(**kwargs: object) -> TLSObservation:
    values = {
        "host": "example.test",
        "port": 443,
        "tls_version": "TLSv1.2",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "subject": "example.test",
        "issuer": "Test CA",
        "san": ("example.test",),
        "not_before": "Jan  1 00:00:00 2026 GMT",
        "not_after": "Jan  1 00:00:00 2027 GMT",
        "hostname_match": True,
        "certificate_error": None,
    }
    values.update(kwargs)
    return TLSObservation(**values)


def test_tls_policy_is_observation_only_when_controls_are_healthy() -> None:
    assert evaluate_tls_observation(_obs(), asset_id=uuid4(), evidence_id=uuid4()) == ()


def test_deprecated_tls_creates_confirmed_high_finding() -> None:
    finding = evaluate_tls_observation(
        _obs(tls_version="TLSv1.1"), asset_id=uuid4(), evidence_id=uuid4()
    )[0]
    assert finding.severity.value == "HIGH"
    assert finding.state.value == "CONFIRMED"
    assert finding.vulnerability_id == "TLS-DEPRECATED-PROTOCOL"


def test_hostname_mismatch_is_evidence_backed() -> None:
    evidence_id = uuid4()
    finding = evaluate_tls_observation(
        _obs(hostname_match=False), asset_id=uuid4(), evidence_id=evidence_id
    )[0]
    assert finding.evidence_ids == (evidence_id,)
    assert finding.vulnerability_id == "TLS-HOSTNAME-MISMATCH"


def test_expired_certificate_is_detected_deterministically() -> None:
    finding = evaluate_tls_observation(
        _obs(not_after="Jan  1 00:00:00 2025 GMT"),
        asset_id=uuid4(),
        evidence_id=uuid4(),
        now=datetime(2026, 1, 2, tzinfo=UTC),
    )[0]
    assert finding.vulnerability_id == "TLS-CERT-EXPIRED"


def test_weak_cipher_creates_medium_finding() -> None:
    finding = evaluate_tls_observation(
        _obs(cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA"), asset_id=uuid4(), evidence_id=uuid4()
    )[0]
    assert finding.severity.value == "MEDIUM"
    assert finding.vulnerability_id == "TLS-WEAK-CIPHER"


def test_certificate_error_creates_high_finding() -> None:
    finding = evaluate_tls_observation(
        _obs(certificate_error="certificate has expired"), asset_id=uuid4(), evidence_id=uuid4()
    )[0]
    assert finding.vulnerability_id == "TLS-CERT-VALIDATION"
    assert finding.evidence_ids
