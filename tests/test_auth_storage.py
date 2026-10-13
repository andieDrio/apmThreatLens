from datetime import UTC, datetime, timedelta

from threatlens.auth import AuthenticationService, Role


def test_auth_tables_are_persisted(postgres_repository):
    auth = AuthenticationService(postgres_repository)
    auth.create_user("admin", "correct horse battery staple", Role.ADMIN)
    assert postgres_repository.count("users") == 1
    assert postgres_repository.count("audit_events") >= 1


def test_postgres_login_rate_limits_are_durable_and_expire(postgres_repository):
    now = datetime.now(UTC)
    keys = ("client:" + "a" * 64, "identity:" + "b" * 64)

    first = postgres_repository.record_login_attempts(keys, now=now, window_seconds=60)
    second = postgres_repository.record_login_attempts(
        keys, now=now + timedelta(seconds=1), window_seconds=60
    )
    after_window = postgres_repository.record_login_attempts(
        keys, now=now + timedelta(seconds=61), window_seconds=60
    )

    assert {key: value[0] for key, value in first.items()} == {key: 1 for key in keys}
    assert {key: value[0] for key, value in second.items()} == {key: 2 for key in keys}
    assert {key: value[0] for key, value in after_window.items()} == {key: 1 for key in keys}
    assert postgres_repository.count("auth_login_rate_limits") == 2
