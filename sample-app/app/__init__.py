"""dsop-evidence-helper — the demonstration containerized workload for the DSOP pipeline.

A small, real REST service: health/version endpoints, a SHA-256/512 hashing endpoint, a UUID
generator, a length-limited echo, and an SBOM validator that checks a CycloneDX or SPDX document
against the NTIA "minimum elements for an SBOM" (2021) — dogfooding the repo's own theme.

Its only purpose here is to give the DevSecOps pipeline a genuine application to build into a
container, scan (SAST/SCA/SBOM/container/DAST/STIG), sign, and produce evidence for. Replace it
with your actual workload (or point the container job at your repo's Dockerfile).
"""

__version__ = "0.2.0"
