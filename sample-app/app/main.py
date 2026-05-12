"""Flask app — the demonstration containerized workload (dsop-evidence-helper).

Secure-by-default so the SAST/IaC/container/DAST gates have a clean baseline to demonstrate:
  * No debug mode (CM-6 / SI-11); no secrets in code (config via environment).
  * Defense-in-depth response headers on every response (CSP, X-Content-Type-Options, ...).
  * Request size caps and input length limits; input is never eval'd / shelled out / templated.
  * Hashing endpoint refuses weak algorithms (no MD5/SHA-1) — SC-13 (use approved cryptography).
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid

import yaml
from flask import Flask, jsonify, request

from . import __version__
from .sbom_check import validate as validate_sbom

MAX_INPUT_LEN = 4096          # max characters of caller-supplied text we'll process
MAX_BODY_BYTES = 2 * 1024 * 1024   # 2 MiB request cap (SBOMs can be a few hundred KB)
APPROVED_HASHES = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512,
                   "sha3_256": hashlib.sha3_256, "sha3_512": hashlib.sha3_512}
WEAK_HASHES = {"md5", "sha1", "md4", "sha-1"}


def create_app() -> Flask:
    app = Flask(__name__)
    # Never enable debug in deployed configurations (CM-6 / SI-11). Honor an env var only for
    # local development; default is off.
    app.config["DEBUG"] = os.environ.get("APP_DEBUG", "").lower() in ("1", "true", "yes")
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    app.config["JSON_SORT_KEYS"] = False

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        resp.headers.pop("Server", None)
        return resp

    # ---- info / health ----------------------------------------------------------------------
    @app.get("/")
    def index():
        return jsonify(
            service="dsop-evidence-helper",
            version=__version__,
            message="DSOP DevSecOps reference pipeline — demonstration workload.",
            endpoints=["/healthz", "/readyz", "/version", "/api/hash (POST)", "/api/uuid",
                       "/api/echo (POST)", "/api/sbom/validate (POST)"],
        )

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/readyz")
    def readyz():
        return jsonify(status="ready")

    @app.get("/version")
    def version():
        return jsonify(version=__version__)

    # ---- hashing (SC-13: approved algorithms only) ------------------------------------------
    @app.post("/api/hash")
    def api_hash():
        data = request.get_json(silent=True) or {}
        algo = str(data.get("algorithm", "sha256")).lower().replace("-", "_")
        text = str(data.get("data", ""))
        if len(text) > MAX_INPUT_LEN:
            return jsonify(error=f"data exceeds {MAX_INPUT_LEN} characters"), 413
        if algo in WEAK_HASHES or algo.replace("_", "") in {"md5", "sha1", "md4"}:
            return jsonify(error=f"algorithm {algo!r} is not permitted (weak); use one of {sorted(APPROVED_HASHES)}"), 422
        fn = APPROVED_HASHES.get(algo)
        if fn is None:
            return jsonify(error=f"unsupported algorithm {algo!r}; supported: {sorted(APPROVED_HASHES)}"), 422
        return jsonify(algorithm=algo, hex=fn(text.encode("utf-8")).hexdigest(), input_length=len(text))

    # ---- uuid -------------------------------------------------------------------------------
    @app.get("/api/uuid")
    def api_uuid():
        return jsonify(uuid=str(uuid.uuid4()), version=4)

    # ---- echo (length-limited; no templating/eval/shell) ------------------------------------
    @app.post("/api/echo")
    def api_echo():
        data = request.get_json(silent=True) or {}
        msg = str(data.get("message", ""))[:MAX_INPUT_LEN]
        return jsonify(echo=msg, length=len(msg))

    # ---- SBOM validation (NTIA minimum elements) — accepts JSON or YAML ----------------------
    @app.post("/api/sbom/validate")
    def api_sbom_validate():
        raw = request.get_data(cache=False, as_text=True) or ""
        if not raw.strip():
            return jsonify(error="empty body — POST a CycloneDX or SPDX SBOM (JSON or YAML)"), 400
        doc = None
        # Try JSON first, then YAML (PyYAML's safe_load parses JSON too, but be explicit).
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            try:
                doc = yaml.safe_load(raw)
            except yaml.YAMLError as exc:
                return jsonify(error=f"could not parse body as JSON or YAML: {exc.__class__.__name__}"), 400
        if not isinstance(doc, dict):
            return jsonify(error="SBOM document must be a JSON/YAML object"), 400
        report = validate_sbom(doc)
        status = 200 if report.get("valid") else 422
        return jsonify(report), status

    # ---- error handlers ---------------------------------------------------------------------
    @app.errorhandler(404)
    def _nf(_e):
        return jsonify(error="not found"), 404

    @app.errorhandler(405)
    def _mna(_e):
        return jsonify(error="method not allowed"), 405

    @app.errorhandler(413)
    def _too_large(_e):
        return jsonify(error="request entity too large"), 413

    return app


# WSGI entrypoint for gunicorn: `gunicorn app.main:app`
app = create_app()


if __name__ == "__main__":  # local dev only — production uses gunicorn (see Dockerfile)
    create_app().run(host="127.0.0.1", port=8080)
