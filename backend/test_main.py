# backend/tests/test_main.py
# Unit and integration tests

import pytest
from fastapi.testclient import TestClient
from ..main import app
from ..database import SessionLocal, engine
from ..models import Base

@pytest.fixture
def client():
    Base.metadata.create_all(bind=engine)
    yield TestClient(app)
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db():
    db = SessionLocal()
    yield db
    db.close()

def test_login_success(client):
    response = client.post("/token", data={"username": "johndoe", "password": "secret"})
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_converse(client, db):
    # Setup: Login to get token
    login_response = client.post("/token", data={"username": "johndoe", "password": "secret"})
    token = login_response.json()["access_token"]
    session_id = login_response.json()["session_id"]
    
    # Test conversation
    response = client.post(
        "/converse",
        json={"message": "Hello", "session_id": session_id},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert "response" in response.json()

# Future: Add tests for brainstorm, think, rate limits, etc.
