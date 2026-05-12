# syntax=docker/dockerfile:1
# ------------------------------------------------------------------------------------------------
# Hardened container image for the demonstration workload.
#
# DoD container-hardening themes (NIST SP 800-190; DISA Container Hardening Process Guide; RAISE 2.0
# container expectations; CM-6 secure settings, CM-7 least functionality, AC-6 least privilege,
# SI-7 provenance/integrity):
#   * Pinned base image (pin by digest in production; consider an Iron Bank / Repo One base image
#     so you inherit DISA's hardening + control evidence — see compliance/crosswalks/raise-2.0-crosswalk.md).
#   * Multi-stage build: build deps never reach the runtime image (minimize attack surface).
#   * Runs as a non-root user with a fixed uid/gid; no shell needed at runtime.
#   * No package manager left writable; apt lists cleaned; --no-install-recommends.
#   * HEALTHCHECK defined; OCI provenance LABELs set.
#   * Read-only root filesystem at runtime is enforced by the orchestrator (see deploy/k8s/).
# ------------------------------------------------------------------------------------------------

ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim AS build
# (Production: replace with e.g. `FROM registry1.dso.mil/ironbank/opensource/python/python3xx:<digest>`)

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---- runtime stage --------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

# Minimal runtime hardening: create an unprivileged user; drop the package cache.
RUN groupadd --gid 10001 app \
 && useradd  --uid 10001 --gid app --no-create-home --home /nonexistent --shell /usr/sbin/nologin app \
 && rm -rf /var/lib/apt/lists/* /root/.cache

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_DEBUG="" \
    PORT=8080

COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY app/ ./app/

USER 10001:10001
EXPOSE 8080

# Liveness probe for container runtimes that honor HEALTHCHECK; k8s uses its own probes (deploy/k8s/).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/opt/venv/bin/python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status==200 else 1)"]

# 2 workers, 4 threads — bind to all interfaces inside the container only.
CMD ["/opt/venv/bin/gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", \
     "--access-logfile", "-", "--error-logfile", "-", "app.main:app"]

# ---- OCI provenance / source-of-truth labels (SI-7 / SR-4) ----------------------------------
LABEL org.opencontainers.image.title="dsop-sample-app" \
      org.opencontainers.image.description="Demonstration workload for the DSOP DevSecOps reference pipeline" \
      org.opencontainers.image.source="https://github.com/your-org/your-repo" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Your Program Office"
