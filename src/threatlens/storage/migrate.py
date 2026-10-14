"""Controlled PostgreSQL schema migration entry point.

Run this as a deployment/migration identity, separately from the API runtime process:
    python -m threatlens.storage.migrate
"""

from __future__ import annotations

import os

from threatlens.storage.postgres import PostgresRepository


def main() -> None:
    dsn = os.getenv("THREATLENS_MIGRATION_DATABASE_URL")
    if not dsn:
        raise SystemExit(
            "THREATLENS_MIGRATION_DATABASE_URL is required for schema migrations"
        )
    repository = PostgresRepository(dsn)
    try:
        repository.initialize()
    finally:
        repository.close()
    print("ThreatLens PostgreSQL schema migrations and audit protections are ready.")


if __name__ == "__main__":
    main()
