"""
Test main application functionality
"""
import pytest
from fastapi.testclient import TestClient


def test_health_check(client: TestClient):
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "KeyHaven Pro API"
    assert data["version"] == "1.0.0"


def test_api_v1_health_check(client: TestClient):
    """Test API v1 health check endpoint"""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["api_version"] == "v1"
    assert data["service"] == "KeyHaven Pro API"


def test_cors_headers(client: TestClient):
    """Test CORS headers are properly set"""
    response = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert response.status_code == 200
    # Check that CORS headers are present
    assert "access-control-allow-origin" in response.headers