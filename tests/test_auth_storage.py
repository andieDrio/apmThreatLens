from threatlens.auth import AuthenticationService, Role

def test_auth_tables_are_persisted(postgres_repository):
    auth=AuthenticationService(postgres_repository)
    auth.create_user("admin","correct horse battery staple",Role.ADMIN)
    assert postgres_repository.count("users")==1
    assert postgres_repository.count("audit_events")>=1
