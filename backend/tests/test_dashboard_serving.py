"""The bare origin must serve the dashboard when one has been built.

A ``StaticFiles`` mount at ``/`` serves ``/index.html`` and ``/assets/*``, but it
does not win for ``/`` itself - the explicit route is registered first, and
routes match in order. So the documented "open http://127.0.0.1:8000" returned a
JSON service descriptor and no dashboard, while every asset around it resolved
correctly. Nothing caught it because no test asked for ``/``.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import DASHBOARD_DIST, app

built = pytest.mark.skipif(
    not (DASHBOARD_DIST / "index.html").is_file(),
    reason="no built dashboard; run 'npm run build' in frontend/",
)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@built
def test_root_serves_the_dashboard(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<!doctype html>" in response.text.lower()


@built
def test_the_bundle_is_reachable_from_the_same_origin(client):
    """The frontend uses relative URLs, so it must be served from the root."""
    index = (DASHBOARD_DIST / "index.html").read_text(encoding="utf-8")
    start = index.index('src="') + 5
    asset = index[start : index.index('"', start)]
    assert client.get(asset).status_code == 200


def test_the_service_descriptor_is_always_available(client):
    """Useful on an API-only checkout, and it must not shadow the dashboard."""
    response = client.get("/api")
    assert response.status_code == 200
    body = response.json()
    assert body["alert_schema_version"] == "1.1"
    assert body["ingest"] == "POST /api/v1/alerts"


def test_the_api_still_answers_under_the_static_mount(client):
    """A mount at "/" must not swallow the routes registered before it."""
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/api/v1/alerts?limit=1").status_code == 200
    assert client.get("/api/v1/system/constraints").status_code == 200


def test_an_unknown_path_does_not_return_the_dashboard_as_an_api_answer(client):
    """html=True makes StaticFiles fall back to index.html.

    That is right for a client-side router and wrong for an API path: a caller
    asking for a route that does not exist should get a 404, not 200 with a page
    of HTML it will try to parse as JSON.
    """
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    assert "text/html" not in response.headers.get("content-type", "")
