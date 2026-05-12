"""Unit tests for the demonstration service. Coverage feeds the build-test gate (SA-11)."""
import hashlib
import json

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
    assert body["service"] == "dsop-evidence-helper"
    assert body["version"] == __version__
    assert "/api/sbom/validate (POST)" in body["endpoints"]


@pytest.mark.parametrize("path,expected", [("/healthz", {"status": "ok"}),
                                           ("/readyz", {"status": "ready"})])
def test_health(client, path, expected):
    r = client.get(path)
    assert r.status_code == 200 and r.get_json() == expected


def test_version(client):
    assert client.get("/version").get_json() == {"version": __version__}


def test_security_headers_present(client):
    r = client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert "Server" not in r.headers


# ---- hash ---------------------------------------------------------------------------------------
def test_hash_sha256_default(client):
    r = client.post("/api/hash", json={"data": "hello"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["algorithm"] == "sha256"
    assert body["hex"] == hashlib.sha256(b"hello").hexdigest()
    assert body["input_length"] == 5


def test_hash_sha512(client):
    r = client.post("/api/hash", json={"data": "abc", "algorithm": "sha512"})
    assert r.get_json()["hex"] == hashlib.sha512(b"abc").hexdigest()


def test_hash_sha3(client):
    r = client.post("/api/hash", json={"data": "x", "algorithm": "sha3-256"})
    assert r.status_code == 200 and r.get_json()["algorithm"] == "sha3_256"


@pytest.mark.parametrize("algo", ["md5", "sha1", "sha-1", "MD5"])
def test_hash_rejects_weak(client, algo):
    r = client.post("/api/hash", json={"data": "x", "algorithm": algo})
    assert r.status_code == 422
    assert "not permitted" in r.get_json()["error"]


def test_hash_rejects_unknown(client):
    r = client.post("/api/hash", json={"data": "x", "algorithm": "rot13"})
    assert r.status_code == 422


def test_hash_rejects_oversized_input(client):
    r = client.post("/api/hash", json={"data": "z" * 5000})
    assert r.status_code == 413


# ---- uuid ---------------------------------------------------------------------------------------
def test_uuid(client):
    import uuid as _uuid
    r = client.get("/api/uuid")
    assert r.status_code == 200
    body = r.get_json()
    assert body["version"] == 4
    _uuid.UUID(body["uuid"], version=4)  # raises if not a valid v4 UUID


# ---- echo ---------------------------------------------------------------------------------------
def test_echo_roundtrip(client):
    assert client.post("/api/echo", json={"message": "hi"}).get_json() == {"echo": "hi", "length": 2}


def test_echo_truncates(client):
    assert client.post("/api/echo", json={"message": "y" * 9000}).get_json()["length"] == 4096


# ---- sbom validate ------------------------------------------------------------------------------
GOOD_CDX = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "metadata": {"timestamp": "2026-05-12T00:00:00Z", "tools": [{"name": "syft"}],
                 "authors": [{"name": "ci"}]},
    "components": [
        {"type": "library", "name": "flask", "version": "3.0.3",
         "purl": "pkg:pypi/flask@3.0.3", "supplier": {"name": "Pallets"}},
        {"type": "library", "name": "pyyaml", "version": "6.0.2",
         "purl": "pkg:pypi/pyyaml@6.0.2", "publisher": "PyYAML"},
    ],
    "dependencies": [{"ref": "root", "dependsOn": ["pkg:pypi/flask@3.0.3"]}],
}


def test_sbom_validate_good_cdx_json(client):
    r = client.post("/api/sbom/validate", data=json.dumps(GOOD_CDX), content_type="application/json")
    assert r.status_code == 200
    body = r.get_json()
    assert body["valid"] is True and body["format"] == "CycloneDX" and body["component_count"] == 2


def test_sbom_validate_good_cdx_yaml(client):
    import yaml as _yaml
    r = client.post("/api/sbom/validate", data=_yaml.safe_dump(GOOD_CDX), content_type="text/yaml")
    assert r.status_code == 200 and r.get_json()["valid"] is True


def test_sbom_validate_missing_elements(client):
    bad = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "components": [{"type": "library", "name": "foo"}]}  # no timestamp/author/version/id/supplier/deps
    r = client.post("/api/sbom/validate", data=json.dumps(bad), content_type="application/json")
    assert r.status_code == 422
    body = r.get_json()
    assert body["valid"] is False and body["issue_count"] >= 4


def test_sbom_validate_spdx(client):
    spdx = {"spdxVersion": "SPDX-2.3",
            "creationInfo": {"created": "2026-05-12T00:00:00Z", "creators": ["Tool: syft"]},
            "packages": [{"name": "flask", "versionInfo": "3.0.3", "supplier": "Organization: Pallets",
                          "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/flask@3.0.3"}]}],
            "relationships": [{"relationshipType": "DEPENDS_ON"}]}
    r = client.post("/api/sbom/validate", data=json.dumps(spdx), content_type="application/json")
    assert r.status_code == 200 and r.get_json()["format"] == "SPDX" and r.get_json()["valid"] is True


def test_sbom_validate_not_an_sbom(client):
    r = client.post("/api/sbom/validate", data=json.dumps({"hello": "world"}), content_type="application/json")
    assert r.status_code == 422 and r.get_json()["format"] == "unknown"


def test_sbom_validate_empty_body(client):
    r = client.post("/api/sbom/validate", data="", content_type="application/json")
    assert r.status_code == 400


def test_sbom_validate_garbage(client):
    r = client.post("/api/sbom/validate", data="{not valid json: [", content_type="application/json")
    assert r.status_code == 400


# ---- misc -------------------------------------------------------------------------------------
def test_not_found(client):
    assert client.get("/nope").status_code == 404


def test_method_not_allowed(client):
    assert client.post("/healthz").status_code == 405
