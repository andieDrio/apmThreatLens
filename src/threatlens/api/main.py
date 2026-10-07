"""Uvicorn entrypoint for the ThreatLens API."""

from threatlens.api.app import create_app

app = create_app()
