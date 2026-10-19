from datetime import UTC, datetime, timedelta
import hashlib

import pytest

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

def test_postgres_login_threshold_audit_is_atomic(postgres_repository):
    key = "identity:" + "c" * 64
    now = datetime.now(UTC)
    connection = postgres_repository.connection

    first = postgres_repository.record_login_attempts(
        (key,),
        now=now,
        window_seconds=60,
        audit_limits={key: (1, "scope=client_username")},
    )
    assert first[key][0] == 1

    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute(
                "DROP TRIGGER IF EXISTS test_fail_login_rate_limit_audit ON audit_events"
            )
            cursor.execute("DROP FUNCTION IF EXISTS test_fail_login_rate_limit_audit()")
            cursor.execute(
                """
                CREATE FUNCTION test_fail_login_rate_limit_audit()
                RETURNS trigger LANGUAGE plpgsql AS $threatlens_login_audit$
                BEGIN
                    IF NEW.action = 'LOGIN_RATE_LIMITED' THEN
                        RAISE EXCEPTION 'injected login rate-limit audit failure';
                    END IF;
                    RETURN NEW;
                END;
                $threatlens_login_audit$
                """
            )
            cursor.execute(
                "CREATE TRIGGER test_fail_login_rate_limit_audit "
                "BEFORE INSERT ON audit_events FOR EACH ROW "
                "EXECUTE FUNCTION test_fail_login_rate_limit_audit()"
            )

    try:
        with pytest.raises(Exception, match="injected login rate-limit audit failure"):
            postgres_repository.record_login_attempts(
                (key,),
                now=now + timedelta(seconds=1),
                window_seconds=60,
                audit_limits={key: (1, "scope=client_username")},
            )

        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT attempts FROM auth_login_rate_limits WHERE bucket_key = %s",
                    (key,),
                )
                assert cursor.fetchone()[0] == 1
                cursor.execute(
                    "SELECT COUNT(*) FROM audit_events WHERE action = %s",
                    ("LOGIN_RATE_LIMITED",),
                )
                assert cursor.fetchone()[0] == 0
    finally:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "DROP TRIGGER IF EXISTS test_fail_login_rate_limit_audit ON audit_events"
                )
                cursor.execute("DROP FUNCTION IF EXISTS test_fail_login_rate_limit_audit()")

    retried = postgres_repository.record_login_attempts(
        (key,),
        now=now + timedelta(seconds=1),
        window_seconds=60,
        audit_limits={key: (1, "scope=client_username")},
    )
    assert retried[key][0] == 2
    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM audit_events WHERE action = %s",
                ("LOGIN_RATE_LIMITED",),
            )
            assert cursor.fetchone()[0] == 1



def test_postgres_failed_login_counter_and_denial_audit_are_atomic(postgres_repository):
    key = "identity:" + "d" * 64
    now = datetime.now(UTC)
    connection = postgres_repository.connection

    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute(
                "DROP TRIGGER IF EXISTS test_fail_login_denial_audit ON audit_events"
            )
            cursor.execute("DROP FUNCTION IF EXISTS test_fail_login_denial_audit()")
            cursor.execute(
                """
                CREATE FUNCTION test_fail_login_denial_audit()
                RETURNS trigger LANGUAGE plpgsql AS $threatlens_failed_login_audit$
                BEGIN
                    IF NEW.action = 'LOGIN' AND NEW.outcome = 'DENIED' THEN
                        RAISE EXCEPTION 'injected failed-login denial audit failure';
                    END IF;
                    RETURN NEW;
                END;
                $threatlens_failed_login_audit$
                """
            )
            cursor.execute(
                "CREATE TRIGGER test_fail_login_denial_audit "
                "BEFORE INSERT ON audit_events FOR EACH ROW "
                "EXECUTE FUNCTION test_fail_login_denial_audit()"
            )

    try:
        with pytest.raises(Exception, match="injected failed-login denial audit failure"):
            with postgres_repository.login_attempt_transaction():
                postgres_repository.record_login_attempts(
                    (key,), now=now, window_seconds=60
                )
                from threatlens.domain.models import AuditEvent

                postgres_repository.save_audit_event(
                    AuditEvent(
                        actor_user_id=None,
                        action="LOGIN",
                        resource_type="AUTH",
                        outcome="DENIED",
                        detail="invalid credentials",
                        created_at=now,
                    )
                )

        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) FROM auth_login_rate_limits WHERE bucket_key = %s",
                    (key,),
                )
                assert cursor.fetchone()[0] == 0
                cursor.execute(
                    "SELECT COUNT(*) FROM audit_events "
                    "WHERE action = %s AND outcome = %s",
                    ("LOGIN", "DENIED"),
                )
                assert cursor.fetchone()[0] == 0
    finally:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "DROP TRIGGER IF EXISTS test_fail_login_denial_audit ON audit_events"
                )
                cursor.execute("DROP FUNCTION IF EXISTS test_fail_login_denial_audit()")

    with postgres_repository.login_attempt_transaction():
        result = postgres_repository.record_login_attempts(
            (key,), now=now, window_seconds=60
        )
        from threatlens.domain.models import AuditEvent

        postgres_repository.save_audit_event(
            AuditEvent(
                actor_user_id=None,
                action="LOGIN",
                resource_type="AUTH",
                outcome="DENIED",
                detail="invalid credentials",
                created_at=now,
            )
        )
    assert result[key][0] == 1
    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT attempts FROM auth_login_rate_limits WHERE bucket_key = %s",
                (key,),
            )
            assert cursor.fetchone()[0] == 1
            cursor.execute(
                "SELECT COUNT(*) FROM audit_events "
                "WHERE action = %s AND outcome = %s",
                ("LOGIN", "DENIED"),
            )
            assert cursor.fetchone()[0] == 1


def test_postgres_logout_session_and_success_audit_are_atomic(postgres_repository):
    auth = AuthenticationService(postgres_repository)
    auth.create_user("logout-atomic", "correct horse battery staple", Role.ANALYST)
    principal, token = auth.authenticate("logout-atomic", "correct horse battery staple")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    connection = postgres_repository.connection

    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute(
                "DROP TRIGGER IF EXISTS test_fail_logout_audit_trigger ON audit_events"
            )
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



def test_postgres_user_creation_and_success_audit_are_atomic(postgres_repository):
    auth = AuthenticationService(postgres_repository)
    connection = postgres_repository.connection

    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute(
                "DROP TRIGGER IF EXISTS test_fail_user_created_audit_trigger ON audit_events"
            )
            cursor.execute("DROP FUNCTION IF EXISTS test_fail_user_created_audit()")
            cursor.execute(
                """
                CREATE OR REPLACE FUNCTION test_fail_user_created_audit()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF NEW.action = 'USER_CREATED' AND NEW.outcome = 'SUCCESS' THEN
                        RAISE EXCEPTION 'injected user creation audit failure';
                    END IF;
                    RETURN NEW;
                END;
                $$
                """
            )
            cursor.execute(
                "CREATE TRIGGER test_fail_user_created_audit_trigger "
                "BEFORE INSERT ON audit_events FOR EACH ROW "
                "EXECUTE FUNCTION test_fail_user_created_audit()"
            )

    def created_user_audit_count():
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) FROM audit_events "
                    "WHERE action = %s AND outcome = %s",
                    ("USER_CREATED", "SUCCESS"),
                )
                return cursor.fetchone()[0]

    try:
        with pytest.raises(Exception, match="injected user creation audit failure"):
            auth.create_user("atomic-user-pg", "correct horse battery staple", Role.ANALYST)

        assert postgres_repository.user_by_username("atomic-user-pg") is None
        assert created_user_audit_count() == 0
    finally:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "DROP TRIGGER IF EXISTS test_fail_user_created_audit_trigger ON audit_events"
                )
                cursor.execute("DROP FUNCTION IF EXISTS test_fail_user_created_audit()")

    user = auth.create_user("atomic-user-pg", "correct horse battery staple", Role.ANALYST)
    assert postgres_repository.user_by_username("atomic-user-pg") == user
    assert created_user_audit_count() == 1
