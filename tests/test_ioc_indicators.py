import pytest

from threatlens.domain.indicators import normalize_ioc_indicator


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("ipv4", "192.0.2.1", "192.0.2.1"),
        ("ipv6", "2001:0DB8::1", "2001:db8::1"),
        ("domain", "BÜCHER.Example.", "xn--bcher-kva.example"),
        ("md5", "A" * 32, "a" * 32),
        ("sha1", "B" * 40, "b" * 40),
        ("sha256", "C" * 64, "c" * 64),
    ],
)
def test_ioc_normalization_canonicalizes_supported_values(kind, value, expected):
    indicator = normalize_ioc_indicator(
        indicator_type=kind, value=value, source="my collection"
    )
    assert indicator.value == expected


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("ipv4", "2001:db8::1"),
        ("ipv6", "192.0.2.1"),
        ("ipv6", "fe80::1%eth0"),
        ("domain", "https://example.com"),
        ("domain", "localhost"),
        ("md5", "not-a-hash"),
        ("sha1", "f" * 39),
        ("sha256", "g" * 64),
        ("url", "https://example.com"),
    ],
)
def test_ioc_normalization_rejects_malformed_or_unsupported_values(kind, value):
    with pytest.raises(ValueError):
        normalize_ioc_indicator(indicator_type=kind, value=value, source="collection")


def test_ioc_normalization_rejects_boolean_confidence_and_invalid_metadata():
    with pytest.raises(ValueError):
        normalize_ioc_indicator(
            indicator_type="ipv4", value="192.0.2.1", source="collection", confidence=True
        )
    with pytest.raises(ValueError):
        normalize_ioc_indicator(
            indicator_type="ipv4", value="192.0.2.1", source="collection", tags=("",)
        )
