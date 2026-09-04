from fastapi.testclient import TestClient
from sentinel.app import VERSION, app
from sentinel.config import get_settings


def test_app_version():
    assert VERSION == "0.1.0"


def test_settings_initialization():
    settings = get_settings()
    assert settings.port > 0
    assert settings.environment in ["development", "production", "test"]


def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
  