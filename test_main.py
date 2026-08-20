import pytest
from fastapi.testclient import TestClient

import jwt

import main


@pytest.fixture()
def client():
    main.redis_client = main.InMemoryRedis()
    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture()
def login_tokens(client):
    response = client.post(
        "/login",
        data={"username": "suraj", "password": "secret123"},
    )
    assert response.status_code == 200
    payload = response.json()
    return payload["access_token"], payload["refresh_token"]


def decode_token(token: str) -> dict:
    return jwt.decode(token, main.SECRET_KEY, algorithms=[main.ALGORITHM])


def test_login_success_returns_access_and_refresh_tokens(client):
    response = client.post(
        "/login",
        data={"username": "suraj", "password": "secret123"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert "access_token" in body
    assert "refresh_token" in body

    access_payload = decode_token(body["access_token"])
    refresh_payload = decode_token(body["refresh_token"])

    assert access_payload["sub"] == "suraj"
    assert access_payload["type"] == "access"
    assert refresh_payload["sub"] == "suraj"
    assert refresh_payload["type"] == "refresh"


@pytest.mark.parametrize(
    "username,password",
    [
        ("suraj", "wrong-password"),
        ("unknown-user", "secret123"),
    ],
)
def test_login_failure_returns_401(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


def test_users_me_with_valid_access_token(client, login_tokens):
    access_token, _ = login_tokens

    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["your_profile"]["username"] == "suraj"
    assert body["your_profile"]["full_name"] == "Suraj Sharma"


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer totally-invalid-token"},
    ],
)
def test_users_me_rejects_missing_or_invalid_access_token(client, headers):
    response = client.get("/users/me", headers=headers)

    assert response.status_code == 401


def test_users_me_rejects_refresh_token(client, login_tokens):
    _, refresh_token = login_tokens

    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Not an access token"


def test_refresh_with_valid_refresh_token_returns_new_access_token(
    client, login_tokens
):
    _, refresh_token = login_tokens

    response = client.post(
        "/refresh",
        json={"refresh_token": refresh_token},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert "access_token" in body

    new_access_payload = decode_token(body["access_token"])
    assert new_access_payload["sub"] == "suraj"
    assert new_access_payload["type"] == "access"


@pytest.mark.parametrize(
    "refresh_token",
    [
        "not-a-token",
    ],
)
def test_refresh_rejects_invalid_refresh_token(client, refresh_token):
    response = client.post(
        "/refresh",
        json={"refresh_token": refresh_token},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Refresh token expired or invalid"


def test_refresh_rejects_access_token(client, login_tokens):
    access_token, _ = login_tokens

    response = client.post(
        "/refresh",
        json={"refresh_token": access_token},
    )

    assert response.status_code == 401
    expected = "Invalid token type. Expected a refresh token."
    assert response.json()["detail"] == expected


def test_logout_revokes_access_token(client, login_tokens):
    access_token, _ = login_tokens

    logout_response = client.post(
        "/logout",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_response.status_code == 200
    assert logout_response.json()["message"] == "Successfully logged out"

    me_response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert me_response.status_code == 401
    expected_revoked = "This token has been revoked (logged out)."
    assert me_response.json()["detail"] == expected_revoked
