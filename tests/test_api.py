"""
tests/test_api.py
CryptAudio Web — Phase 2 API Tests

Tests the FastAPI backend foundation using FastAPI's built-in TestClient (httpx).

Run:
    .venv\\Scripts\\python.exe -m pytest tests/test_api.py -v
"""

from __future__ import annotations

import sys
import os

import pytest
from fastapi.testclient import TestClient

# Ensure the project root is on sys.path so `app.*` imports resolve correctly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.main import app  # noqa: E402  (import after path fix)
from app.core.config import settings  # noqa: E402

# ---------------------------------------------------------------------------
# Shared client fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client() -> TestClient:
    """Return a synchronous test client for the FastAPI app."""
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# 1. Application initialisation
# ---------------------------------------------------------------------------

def test_application_initialises() -> None:
    """The FastAPI application object must be importable and have the correct title."""
    assert app is not None
    assert app.title == settings.APP_TITLE


# ---------------------------------------------------------------------------
# 2–4. Health endpoint
# ---------------------------------------------------------------------------

def test_health_returns_200(client: TestClient) -> None:
    """GET /api/health must return HTTP 200."""
    response = client.get("/api/health")
    assert response.status_code == 200


def test_health_response_contains_application_name(client: TestClient) -> None:
    """Health payload must include the correct application name."""
    response = client.get("/api/health")
    body = response.json()
    assert "application" in body
    assert body["application"] == settings.APP_NAME


def test_health_response_contains_version(client: TestClient) -> None:
    """Health payload must include the correct version string."""
    response = client.get("/api/health")
    body = response.json()
    assert "version" in body
    assert body["version"] == settings.APP_VERSION


def test_health_response_status_field(client: TestClient) -> None:
    """Health payload must include status == 'healthy'."""
    response = client.get("/api/health")
    body = response.json()
    assert body.get("status") == "healthy"


# ---------------------------------------------------------------------------
# 5–6. Root / static serving
# ---------------------------------------------------------------------------

def test_root_returns_200(client: TestClient) -> None:
    """GET / must return HTTP 200."""
    response = client.get("/")
    assert response.status_code == 200


def test_root_serves_html(client: TestClient) -> None:
    """GET / must respond with an HTML content-type."""
    response = client.get("/")
    content_type = response.headers.get("content-type", "")
    assert "text/html" in content_type


def test_root_body_contains_title(client: TestClient) -> None:
    """The index page must contain the expected document title."""
    response = client.get("/")
    assert "CryptAudio Web" in response.text


# ---------------------------------------------------------------------------
# 7. Unknown routes
# ---------------------------------------------------------------------------

def test_unknown_route_returns_404(client: TestClient) -> None:
    """Requests to undefined routes must return HTTP 404."""
    response = client.get("/this-route-does-not-exist")
    assert response.status_code == 404


def test_unknown_api_route_returns_404(client: TestClient) -> None:
    """Requests to undefined API routes must return HTTP 404."""
    response = client.get("/api/nonexistent")
    assert response.status_code == 404
