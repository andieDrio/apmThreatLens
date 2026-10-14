import hashlib

import pytest

from threatlens.auth import AuthenticationService, Permission, Role
from threatlens.storage.sqlite import SQLiteRepository


def test_login_role_and_session_round_trip(tmp_path):
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    auth = AuthenticationService(repo, session_ttl_seconds=600)
    user = auth.create_user("analyst", "correct horse battery staple", Role.ANALYST)
    principal, token = auth.authenticate("analyst", "correct horse battery staple")
    assert principal.user_id == user.id
    assert principal.role is Role.ANALYST
    assert auth.authenticate_session(token) == principal
    auth.authorize(principal, Permission.ASSESS)
    repo.close()


def test_invalid_credentials_fail_closed(tmp_path):
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    auth = AuthenticationService(repo)
    auth.create_user("viewer", "correct horse battery staple", Role.VIEWER)
    with pytest.raises(PermissionError, match="authentication failed"):
        auth.authenticate("viewer", "wrong password")
    repo.close()


def test_viewer_cannot_assess(tmp_path):
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    auth = AuthenticationService(repo)
    auth.create_user("viewer", "correct horse battery staple", Role.VIEWER)
    principal, _ = auth.authenticate("viewer", "correct horse battery staple")
    with pytest.raises(PermissionError, match="insufficient permission"):
        auth.authorize(principal, Permission.ASSESS)
    repo.close()


def test_logout_revokes_session(tmp_path):
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    auth = AuthenticationService(repo)
    auth.create_user("analyst", "correct horse battery staple", Role.ANALYST)
    principal, token = auth.authenticate("analyst", "correct horse battery staple")
    auth.logout(principal)
    with pytest.raises(PermissionError, match="session is invalid"):
        auth.authenticate_session(token)
    repo.close()

def test_logout_session_and_success_audit_are_atomic_on_audit_failure(tmp_path):
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    auth = AuthenticationService(repo)
    auth.create_user("analyst", "correct horse battery staple", Role.ANALYST)
    principal, token = auth.authenticate("analyst", "correct horse battery staple")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    repo.connection.execute(
        """
        CREATE TRIGGER fail_logout_success_audit
        BEFORE INSERT ON audit_events
        WHEN NEW.action = 'LOGOUT' AND NEW.outcome = 'SUCCESS'
        BEGIN
            SELECT RAISE(ABORT, 'injected logout audit failure');
        END
        """
    )

    with pytest.raises(Exception, match="injected logout audit failure"):
        auth.logout(principal)

    session = repo.session_by_token_hash(token_hash)
    assert session is not None
    assert session["revoked"] is False
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='LOGOUT' AND outcome='SUCCESS'"
    ).fetchone()[0] == 0

    repo.connection.execute("DROP TRIGGER fail_logout_success_audit")
    auth.logout(principal)
    session = repo.session_by_token_hash(token_hash)
    assert session["revoked"] is True
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='LOGOUT' AND outcome='SUCCESS'"
    ).fetchone()[0] == 1
    repo.close()


@pytest.mark.parametrize("iterations", ["0", "999999999", "10000"])
def test_password_verifier_rejects_unsafe_pbkdf2_cost(iterations):
    encoded = f"pbkdf2_sha256${iterations}${'00' * 16}${'00' * 32}"
    assert not AuthenticationService._verify_password("password", encoded)


def test_password_verifier_rejects_malformed_salt_or_digest():
    assert not AuthenticationService._verify_password(
        "password", "pbkdf2_sha256$600000$00$" + "00" * 32
    )
    assert not AuthenticationService._verify_password(
        "password", "pbkdf2_sha256$600000$" + "00" * 16 + "$00"
    )


def test_login_with_unsupported_persisted_role_fails_closed_and_audits(tmp_path):
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    auth = AuthenticationService(repo)
    user = auth.create_user("analyst", "correct horse battery staple", Role.ANALYST)
    with repo.connection:
        repo.connection.execute("UPDATE users SET role = ? WHERE id = ?", ("ROOT", str(user.id)))

    with pytest.raises(PermissionError, match="authentication failed"):
        auth.authenticate("analyst", "correct horse battery staple")

    events = repo.connection.execute(
        "SELECT action, outcome, detail FROM audit_events "
        "WHERE actor_user_id = ? ORDER BY created_at DESC",
        (str(user.id),),
    ).fetchall()
    assert any(
        event["action"] == "LOGIN"
        and event["outcome"] == "DENIED"
        and event["detail"] == "invalid stored role"
        for event in events
    )
    assert repo.connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0
    repo.close()


def test_existing_session_with_unsupported_persisted_role_fails_closed(tmp_path):
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    auth = AuthenticationService(repo)
    user = auth.create_user("analyst", "correct horse battery staple", Role.ANALYST)
    _, token = auth.authenticate("analyst", "correct horse battery staple")
    with repo.connection:
        repo.connection.execute("UPDATE users SET role = ? WHERE id = ?", ("ROOT", str(user.id)))

    with pytest.raises(PermissionError, match="session is invalid or expired"):
        auth.authenticate_session(token)
    repo.close()

@pytest.mark.parametrize("corruption", ["expires_at", "session_id", "user_id"])
def test_corrupt_persisted_session_fails_closed(tmp_path, corruption):
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    auth = AuthenticationService(repo)
    auth.create_user("analyst", "correct horse battery staple", Role.ANALYST)
    _, token = auth.authenticate("analyst", "correct horse battery staple")
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    if corruption == "expires_at":
        with repo.connection:
            repo.connection.execute(
                "UPDATE auth_sessions SET expires_at = ? WHERE token_hash = ?",
                ("not-a-timestamp", token_hash),
            )
    elif corruption == "session_id":
        with repo.connection:
            repo.connection.execute(
                "UPDATE auth_sessions SET id = ? WHERE token_hash = ?",
                ("not-a-uuid", token_hash),
            )
    else:
        repo.connection.execute("PRAGMA foreign_keys = OFF")
        with repo.connection:
            repo.connection.execute(
                "UPDATE auth_sessions SET user_id = ? WHERE token_hash = ?",
                ("not-a-uuid", token_hash),
            )
        repo.connection.execute("PRAGMA foreign_keys = ON")

    with pytest.raises(PermissionError, match="session is invalid or expired"):
        auth.authenticate_session(token)
    repo.close()

def test_login_session_and_success_audit_are_atomic_on_audit_failure(tmp_path):
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    auth = AuthenticationService(repo)
    auth.create_user("analyst", "correct horse battery staple", Role.ANALYST)
    repo.connection.execute(
        """
        CREATE TRIGGER fail_login_success_audit
        BEFORE INSERT ON audit_events
        WHEN NEW.action = 'LOGIN' AND NEW.outcome = 'SUCCESS'
        BEGIN
            SELECT RAISE(ABORT, 'injected login audit failure');
        END
        """
    )
    with pytest.raises(Exception, match="injected login audit failure"):
        auth.authenticate("analyst", "correct horse battery staple")
    assert repo.connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='LOGIN' AND outcome='SUCCESS'"
    ).fetchone()[0] == 0
    repo.connection.execute("DROP TRIGGER fail_login_success_audit")
    principal, token = auth.authenticate("analyst", "correct horse battery staple")
    assert auth.authenticate_session(token) == principal
    assert repo.connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 1
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='LOGIN' AND outcome='SUCCESS'"
    ).fetchone()[0] == 1
    repo.close()



def test_user_creation_and_success_audit_are_atomic_on_audit_failure(tmp_path):
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    auth = AuthenticationService(repo)
    repo.connection.execute(
        """
        CREATE TRIGGER fail_user_created_audit
        BEFORE INSERT ON audit_events
        WHEN NEW.action = 'USER_CREATED' AND NEW.outcome = 'SUCCESS'
        BEGIN
            SELECT RAISE(ABORT, 'injected user creation audit failure');
        END
        """
    )

    with pytest.raises(Exception, match="injected user creation audit failure"):
        auth.create_user("atomic-user", "correct horse battery staple", Role.ANALYST)

    assert repo.user_by_username("atomic-user") is None
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='USER_CREATED' AND outcome='SUCCESS'"
    ).fetchone()[0] == 0

    repo.connection.execute("DROP TRIGGER fail_user_created_audit")
    user = auth.create_user("atomic-user", "correct horse battery staple", Role.ANALYST)
    assert repo.user_by_username("atomic-user") == user
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='USER_CREATED' AND outcome='SUCCESS'"
    ).fetchone()[0] == 1
    repo.close()
