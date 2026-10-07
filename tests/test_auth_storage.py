from threatlens.auth import AuthenticationService, Role
from threatlens.storage.sqlite import SQLiteRepository


def test_auth_tables_are_persisted(tmp_path):
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    auth = AuthenticationService(repo)
    auth.create_user("admin", "correct horse battery staple", Role.ADMIN)
    assert repo.count("users") == 1
    assert repo.count("audit_events") >= 1
    repo.close()
