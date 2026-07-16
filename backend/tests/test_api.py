import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base, get_db
from app.models import User, SigmaRule, RawEvent, Alert, Incident
from app.main import app
from fastapi.testclient import TestClient

TEST_DATABASE_URL = "sqlite:///./test_temp.db"

engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def test_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(test_db):
    def override_get_db():
        try:
            yield test_db
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()

def test_register_and_login_flow(client):
    # 1. Register a new user
    reg_response = client.post(
        "/api/auth/register",
        json={"username": "testanalyst", "password": "securepassword123", "role": "analyst"}
    )
    assert reg_response.status_code == 200
    assert reg_response.json()["username"] == "testanalyst"
    assert "password_hash" not in reg_response.json()

    # 2. Prevent duplicate registrations
    duplicate_response = client.post(
        "/api/auth/register",
        json={"username": "testanalyst", "password": "differentpassword", "role": "analyst"}
    )
    assert duplicate_response.status_code == 400

    # 3. Successful login
    login_response = client.post(
        "/api/auth/login",
        json={"username": "testanalyst", "password": "securepassword123"}
    )
    assert login_response.status_code == 200
    login_data = login_response.json()
    assert "access_token" in login_data
    assert login_data["username"] == "testanalyst"
    assert login_data["role"] == "analyst"

    # 4. Failed login
    failed_login = client.post(
        "/api/auth/login",
        json={"username": "testanalyst", "password": "wrongpassword"}
    )
    assert failed_login.status_code == 401

def test_authenticated_route_access(client):
    # 1. Accessing /me without authentication fails
    unauth_response = client.get("/api/auth/me")
    assert unauth_response.status_code == 401

    # 2. Register, login and access /me with token
    client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "password123", "role": "admin"}
    )
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "testuser", "password": "password123"}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    auth_response = client.get("/api/auth/me", headers=headers)
    assert auth_response.status_code == 200
    assert auth_response.json()["username"] == "testuser"
    assert auth_response.json()["role"] == "admin"

def test_fetch_incidents_rules_and_alerts(client):
    # Retrieve rules (initially bootstrapped)
    rules_resp = client.get("/api/rules")
    assert rules_resp.status_code == 200
    rules = rules_resp.json()
    # Should bootstrap rules from disk since DB is empty
    assert len(rules) > 0
    assert any(r["id"] == "mimikatz_detection" for r in rules)

    # Fetch incidents list (should be empty initially)
    incidents_resp = client.get("/api/incidents")
    assert incidents_resp.status_code == 200
    assert incidents_resp.json() == []

    # Fetch alerts list (should be empty initially)
    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.status_code == 200
    assert alerts_resp.json() == []

def test_simulator_trigger_invalid(client):
    # Trigger simulator with invalid scenario name returns 400
    response = client.post("/api/simulator/trigger?scenario=nonexistent")
    assert response.status_code == 400
