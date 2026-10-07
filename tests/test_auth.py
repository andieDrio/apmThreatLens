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
