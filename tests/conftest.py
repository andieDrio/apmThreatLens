"""Shared pytest configuration for canonical PostgreSQL integration tests."""

import os

import pytest
from psycopg.conninfo import conninfo_to_dict

from postgres_support import postgres_repository  # noqa: F401


@pytest.fixture(scope="session", autouse=True)
def require_dedicated_postgres_test_database():
    """Fail before tests can mutate any database other than the disposable test DB."""
    dsn = os.getenv("THREATLENS_TEST_DATABASE_URL")
    if dsn and conninfo_to_dict(dsn).get("dbname") != "threatlens_test":
        pytest.fail(
            "THREATLENS_TEST_DATABASE_URL must point to the dedicated threatlens_test database"
        )
