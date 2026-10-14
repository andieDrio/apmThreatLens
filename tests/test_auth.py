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
