import sqlite3

import pytest

from threatlens.domain.indicators import normalize_ioc_indicator
from threatlens.domain.models import AuditEvent
from threatlens.storage.sqlite import SQLiteRepository


def test_sqlite_ioc_import_upserts_and_writes_audit_atomically(tmp_path):
    repository = SQLiteRepository(tmp_path / "ioc.sqlite3")
    repository.initialize()
    indicator = normalize_ioc_indicator(
        indicator_type="domain",
        value="Example.COM.",
        source="personal-feed",
        tags=("phishing",),
    )
    audit = AuditEvent(
        action="IOC_INDICATORS_IMPORTED",
        resource_type="ioc_indicators",
        outcome="SUCCESS",
        detail='{"indicator_count":1}',
    )
    try:
        assert repository.save_ioc_indicators((indicator,), audit) == 1
        duplicate = normalize_ioc_indicator(
            indicator_type="domain",
            value="example.com",
            source="updated-feed",
            confidence=0.7,
        )
        assert repository.save_ioc_indicators(
            (duplicate,),
            AuditEvent(
                action="IOC_IMPORT",
                resource_type="ioc_indicators",
                outcome="SUCCESS",
                detail='{"indicator_count":1}',
            ),
        ) == 1

        result = repository.ioc_indicators_read_model(limit=1)
        assert result["total"] == 1
        assert result["items"][0]["value"] == "example.com"
        assert result["items"][0]["source"] == "updated-feed"
        assert result["items"][0]["confidence"] == 0.7
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM audit_events "
            "WHERE action IN ('IOC_INDICATORS_IMPORTED','IOC_IMPORT')"
        ).fetchone()[0] == 2
        with pytest.raises(ValueError, match="pagination"):
            repository.ioc_indicators_read_model(offset=1_000_001)

        with pytest.raises(sqlite3.IntegrityError):
            repository.save_ioc_indicators((
                normalize_ioc_indicator(
                    indicator_type="ipv4", value="192.0.2.9", source="rollback-test"
                ),
            ), audit)
        assert repository.ioc_indicators_read_model()["total"] == 1
    finally:
        repository.close()
