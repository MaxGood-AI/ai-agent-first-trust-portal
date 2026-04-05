"""Tests for CRUD API routes."""

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, Control, System
from app.services import team_service


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers(app):
    with app.app_context():
        member = team_service.create_member("API User", "api@test.com", "human")
        return {"X-API-Key": member.api_key}


def test_crud_list_controls(client, auth_headers, app):
    with app.app_context():
        c = Control(id="ctrl-1", name="Test", category="security")
        db.session.add(c)
        db.session.commit()

    resp = client.get("/api/controls", headers=auth_headers)
    # Note: the original /api/controls route exists too; CRUD registers
    # on the same path. Both return lists. Let's just verify it works.
    assert resp.status_code == 200


def test_crud_create_and_get_system(client, auth_headers):
    resp = client.post("/api/systems", json={
        "name": "New System",
        "short_name": "new-sys",
        "provider": "AWS",
    }, headers=auth_headers)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["name"] == "New System"
    assert data["id"]  # auto-generated

    # Get by ID
    resp2 = client.get(f"/api/systems/{data['id']}", headers=auth_headers)
    assert resp2.status_code == 200
    assert resp2.get_json()["name"] == "New System"


def test_crud_update_system(client, auth_headers, app):
    with app.app_context():
        s = System(id="sys-upd", name="Old Name", short_name="old")
        db.session.add(s)
        db.session.commit()

    resp = client.put("/api/systems/sys-upd", json={"name": "New Name"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "New Name"


def test_crud_delete_system(client, auth_headers, app):
    with app.app_context():
        s = System(id="sys-del", name="Delete Me")
        db.session.add(s)
        db.session.commit()

    resp = client.delete("/api/systems/sys-del", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["deleted"] == "sys-del"

    resp2 = client.get("/api/systems/sys-del", headers=auth_headers)
    assert resp2.status_code == 404


def test_crud_get_404(client, auth_headers):
    resp = client.get("/api/systems/nonexistent", headers=auth_headers)
    assert resp.status_code == 404


def test_crud_create_missing_required(client, auth_headers):
    resp = client.post("/api/systems", json={"short_name": "no-name"}, headers=auth_headers)
    assert resp.status_code == 400
    assert "Missing required field: name" in resp.get_json()["error"]


def test_crud_requires_auth(client):
    resp = client.get("/api/systems")
    assert resp.status_code == 401
