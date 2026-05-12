"""Demonstration containerized service for the DSOP DevSecOps reference pipeline.

This is intentionally tiny: its only job is to give the pipeline a real thing to build, test,
scan (SAST/SCA/SBOM/container/DAST/STIG), sign, and produce evidence for. Replace it with your
actual workload (or point the container job at your repo's Dockerfile).
"""

__version__ = "0.1.0"
