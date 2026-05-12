"""Unit tests for the demonstration service. Coverage feeds the build-test gate (SA-11)."""
import pytest

from app import __version__
from app.main import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def test_index(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.get_json()
    assert body["service"] == "dsop-sample-app"
    assert body["version"] == __version__


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok"}


def test_readyz(client):
    assert client.get("/readyz").get_json() == {"status": "ready"}


def test_version(client):
    assert client.get("/version").get_json() == {"version": __version__}


def test_echo_roundtrip(client):
    r = client.post("/echo", json={"message": "hello"})
    assert r.status_code == 200
    assert r.get_json() == {"echo": "hello", "length": 5}


def test_echo_truncates_long_input(client):
    long = "x" * 1000
    r = client.post("/echo", json={"message": long})
    assert r.get_json()["length"] == 256


def test_echo_empty(client):
    r = client.post("/echo", json={})
    assert r.get_json() == {"echo": "", "length": 0}


def test_security_headers_present(client):
    r = client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert "Server" not in r.headers


def test_not_found(client):
    r = client.get("/nope")
    assert r.status_code == 404
    assert r.get_json()["error"] == "not found"


def test_method_not_allowed(client):
    r = client.post("/healthz")
    assert r.status_code == 405
