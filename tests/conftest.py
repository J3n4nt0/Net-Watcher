import pytest
from fastapi.testclient import TestClient
from main import app  

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def auth_headers(client):
    # login once per test
    response = client.post(
        "/login",
        json={"username": "admin", "password": "admin"}
    )
    assert response.status_code == 200
    token = response.json()["token"]  
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def admin_client(client, auth_headers):
    client.headers.update(auth_headers)
    return client


def test_logout(auth_headers, client):
    response = client.post("/logout", headers=auth_headers)
    assert response.status_code == 200

def test_something_protected(admin_client):
    response = admin_client.get("/admin-only")
    assert response.status_code == 200

def test_something_protected2(auth_headers, client):
    response = client.get("/me", headers=auth_headers)
    assert response.status_code == 200

