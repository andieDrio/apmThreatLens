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

def test_postgres_logout_session_and_success_audit_are_atomic(postgres_repository):
    import hashlib

    import pytest

    auth = AuthenticationService(postgres_repository)
    auth.create_user("logout-atomic", "correct horse battery staple", Role.ANALYST)
    principal, token = auth.authenticate("logout-atomic", "correct horse battery staple")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    connection = postgres_repository.connection

    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute("DROP TRIGGER IF EXISTS test_fail_logout_audit_trigger ON audit_events")
            cursor.execute("DROP FUNCTION IF EXISTS test_fail_logout_audit()")
            cursor.execute(
                """
                CREATE OR REPLACE FUNCTION test_fail_logout_audit()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF NEW.action = 'LOGOUT' AND NEW.outcome = 'SUCCESS' THEN
                        RAISE EXCEPTION 'injected logout audit failure';
                    END IF;
                    RETURN NEW;
                END;
                $$
                """
            )
            cursor.execute(
                "CREATE TRIGGER test_fail_logout_audit_trigger "
                "BEFORE INSERT ON audit_events FOR EACH ROW "
                "EXECUTE FUNCTION test_fail_logout_audit()"
            )

    def logout_success_count():
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) FROM audit_events "
                    "WHERE action = %s AND outcome = %s",
                    ("LOGOUT", "SUCCESS"),
                )
                return cursor.fetchone()[0]

    try:
        with pytest.raises(Exception, match="injected logout audit failure"):
            auth.logout(principal)

        session = postgres_repository.session_by_token_hash(token_hash)
        assert session is not None
        assert session["revoked"] is False
        assert logout_success_count() == 0
    finally:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "DROP TRIGGER IF EXISTS test_fail_logout_audit_trigger ON audit_events"
                )
                cursor.execute("DROP FUNCTION IF EXISTS test_fail_logout_audit()")

    auth.logout(principal)
    session = postgres_repository.session_by_token_hash(token_hash)
    assert session["revoked"] is True
    assert logout_success_count() == 1
