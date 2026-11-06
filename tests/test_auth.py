from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

auth_header = ""

def test_login():
    global auth_header
    response = client.post(
        "/login",
        json={
            "username": "admin",
            "password": "admin"
        })
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "admin"
    auth_header = {"Authorization" : f"Bearer {data["token"]}"}

def test_me():
    response = client.get("/me" , headers = auth_header)
    assert response.status_code == 200
'''
def test_create_user():
    data = {"username":"test", "password":"what3ver" , "role":"guest"}
    response = client.post("/users" , 
                           headers = auth_header, 
                           json = data
            )
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] == True

def test_delete_user():
    response = client.delete("/user/4" , headers = auth_header)
    assert response.json()["ok"] == True
'''

def test_logout():
    response = client.post(
        "/logout", 
        headers = auth_header
    )
    assert response.status_code == 200

