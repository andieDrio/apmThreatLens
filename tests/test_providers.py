from threatlens.providers.interfaces import (
    AssessmentProvider,
    DiscoveryProvider,
    EvidenceProvider,
    NetworkScannerProvider,
)


def test_provider_protocols_exist() -> None:
    assert DiscoveryProvider
    assert NetworkScannerProvider
    assert AssessmentProvider
    assert EvidenceProvider
