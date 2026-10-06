import pytest

from threatlens.providers.identification import Protocol, normalize_observation


def test_normalizes_http_server_metadata() -> None:
    observation = normalize_observation(
        port=80,
        banner="HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n",
    )

    assert observation.protocol is Protocol.HTTP
    assert observation.service_name == "http"
    assert observation.product == "nginx"
    assert observation.version == "1.24.0"
    assert observation.confidence >= 0.9


def test_normalizes_ssh_banner() -> None:
    observation = normalize_observation(port=22, banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")

    assert observation.protocol is Protocol.SSH
    assert observation.product == "OpenSSH_9.6p1"
    assert observation.version == "Ubuntu-3ubuntu13"


def test_explicit_protocol_is_authoritative() -> None:
    observation = normalize_observation(port=8443, protocol="https")
    assert observation.protocol is Protocol.HTTPS
    assert observation.service_name == "https"


def test_unknown_explicit_protocol_does_not_create_a_claim() -> None:
    observation = normalize_observation(port=12345, protocol="future-protocol")
    assert observation.protocol is Protocol.UNKNOWN
    assert observation.confidence < 0.5


def test_banner_is_bounded() -> None:
    with pytest.raises(ValueError):
        normalize_observation(port=80, banner="A" * 8193)


def test_null_bytes_are_removed_before_normalization() -> None:
    observation = normalize_observation(port=80, banner="\x00HTTP/1.1 200 OK\r\nServer: caddy/2.8.4\r\n")
    assert observation.product == "caddy"
    assert observation.version == "2.8.4"
