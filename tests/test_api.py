import pytest
from fastapi.testclient import TestClient
from main import app

@pytest.fixture
def admin_client():
    client = TestClient(app)
    response = client.post("/login",
        json={"username": "admin","password": "admin"}
    )
    assert response.status_code == 200
    token = response.json()["token"]
    
    client.headers = {"Authorization": f"Bearer {token}"}
    return client

# ---------- User management test --------------

def test_me(admin_client):
    response = admin_client.get("/me")
    assert response.status_code == 200

'''
def test_create_user(admin_client):
    data = {"username":"test", "password":"what3ver" , "role":"guest"}
    response = admin_client.post("/users" ,json = data)
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] == True

def test_delete_user():
    response = client.delete("/user/4" , headers = admin_token)
    assert response.json()["ok"] == True
'''
def test_logout(admin_client):
    response = admin_client.post("/logout")
    assert response.status_code == 200

def test_get_users_list(admin_client):
    response = admin_client.get("/users")
    assert response.status_code == 200

# --------- Monitoring managements test -------------

def test_hosts_alive(admin_client):
    body = ["127.0.0/30", "127.0.0.1"]
    response = admin_client.get("/hosts?subnet=127.0.0.1/30&ips=127.0.0.1")
    assert response.status_code == 200
    assert len(response.json()["alive"]) == 2

def test_get_ping_history(admin_client):
    response = admin_client.get("/ping-history?ip=127.3.0.1")
    assert response.status_code == 200
def test_get_monitor_summary(admin_client):
    response = admin_client.get("/monitor/summary")
    assert response.status_code == 200

# ------------ Device management test ---------

