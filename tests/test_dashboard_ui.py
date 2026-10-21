import httpx
import pytest

from threatlens.api.app import create_app


@pytest.mark.anyio
async def test_dashboard_ui_serves_static_assets_with_security_headers():
    app = create_app(
        repository=object(),
        auth_service=object(),
        orchestrator=object(),
        provider_registry=object(),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        page = await client.get("/")
        script = await client.get("/ui/assets/app.js")
        stylesheet = await client.get("/ui/assets/styles.css")

    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in page.headers["content-security-policy"]
    assert 'id="login-form"' in page.text
    assert 'id="severity-breakdown"' in page.text
    assert 'id="campaigns"' in page.text
    assert 'id="report-campaign-select"' in page.text
    assert 'id="download-campaign-report"' in page.text
    assert "Campaigns scoped · rollout in progress" in page.text
    assert "scan controls, aggregates, and audit views still need organization scoping" in page.text
    assert 'id="evidence"' in page.text
    assert 'id="attack-paths"' in page.text
    assert 'id="audit-log"' in page.text
    assert 'aria-current="page"' in page.text
    assert "/ui/assets/app.js" in page.text
    assert script.status_code == 200
    assert "sessionStorage" in script.text
    assert "/api/v1/campaigns?limit=100&offset=0" in script.text
    assert "/report`" in script.text
    assert "createObjectURL" in script.text
    assert "/api/v1/evidence?limit=8&offset=0" in script.text
    assert "/api/v1/attack-path/relations?limit=8&offset=0" in script.text
    assert "/api/v1/audit-events?limit=8&offset=0" in script.text
    assert "localStorage" not in script.text
    assert "updateActiveNavigation" in script.text
    assert "aria-current" in script.text
    assert stylesheet.status_code == 200
    assert ".metric-grid" in stylesheet.text
    assert ":focus-visible" in stylesheet.text
    assert "prefers-reduced-motion: reduce" in stylesheet.text


@pytest.mark.anyio
async def test_login_fails_closed_without_durable_rate_limiter():
    app = create_app(
        repository=object(),
        auth_service=object(),
        orchestrator=object(),
        provider_registry=object(),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={"username": "operator", "password": "correct-horse-battery-123"},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == "durable login protection unavailable"
