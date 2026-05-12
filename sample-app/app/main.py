"""Minimal Flask service — health, version, and a trivial echo endpoint.

Secure-by-default notes (so the SAST/IaC/container gates have a clean baseline to demonstrate):
  * No debug mode; no secrets in code (config via environment).
  * JSON responses with explicit content type; basic security headers set on every response.
  * Input is length-limited and never eval'd / shelled out.
"""
from __future__ import annotations

import os

from flask import Flask, jsonify, request

from . import __version__

MAX_INPUT_LEN = 256


def create_app() -> Flask:
    app = Flask(__name__)
    # Never enable debug in deployed configurations (CM-6 / SI-11). Honor an env var only for
    # local development; default is off.
    app.config["DEBUG"] = os.environ.get("APP_DEBUG", "").lower() in ("1", "true", "yes")
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KiB request cap

    @app.after_request
    def _security_headers(resp):
        # Defense-in-depth headers (the ZAP baseline checks for these; SC-8/SC-18 themes).
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        resp.headers.pop("Server", None)
        return resp

    @app.get("/")
    def index():
        return jsonify(service="dsop-sample-app", version=__version__,
                       message="DSOP DevSecOps reference pipeline — sample workload.")

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/readyz")
    def readyz():
        return jsonify(status="ready")

    @app.get("/version")
    def version():
        return jsonify(version=__version__)

    @app.post("/echo")
    def echo():
        data = request.get_json(silent=True) or {}
        msg = str(data.get("message", ""))[:MAX_INPUT_LEN]
        # Echo back exactly what was sent (length-limited, stringified) — no templating, no eval.
        return jsonify(echo=msg, length=len(msg))

    @app.errorhandler(404)
    def _nf(_e):
        return jsonify(error="not found"), 404

    @app.errorhandler(405)
    def _mna(_e):
        return jsonify(error="method not allowed"), 405

    return app


# WSGI entrypoint for gunicorn: `gunicorn app.main:app`
app = create_app()


if __name__ == "__main__":  # local dev only — production uses gunicorn (see Dockerfile)
    create_app().run(host="127.0.0.1", port=8080)
