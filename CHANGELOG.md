# Changelog

All notable changes to this system are recorded here. This is a **RAISE 2.0 Application-Owner
artifact** (the CHANGELOG / Release Notes — a historical record of all production changes per
version) and contributes to **SA-10** (developer configuration management — release records). One
entry per release; reference the PRs and any POA&M items closed.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/); versions follow
[SemVer](https://semver.org/). Each release tag (`vX.Y.Z`) triggers the `emass-package-release`
workflow, which builds the eMASS submission package and attaches it to the GitHub Release.

## [Unreleased]
### Added
- Initial DSOP DevSecOps reference pipeline: GitHub-native CI/CD with SAST (CodeQL + Semgrep), SCA
  (Trivy/Grype/OWASP Dependency-Check), SBOM (Syft → SPDX 2.3 + CycloneDX 1.5), secrets scanning
  (Gitleaks/TruffleHog), IaC scanning (Checkov/KICS/Trivy-config/kube-linter/Conftest-OPA),
  container build + scan + Hadolint/Dockle + cosign signing + SLSA build provenance, DAST (OWASP
  ZAP), STIG/SCAP (OpenSCAP placeholder), license policy, and OpenSSF Scorecard.
- Body-of-Evidence engine (`scripts/`): normalize all scanner outputs → map to NIST SP 800-53 Rev 5
  controls → generate the POA&M (eMASS layout) → ConMon trend → eMASS submission package → AO
  dashboard data.
- AO/SCA/ISSM dashboard (GitHub Pages) + auto-maintained "ATO Status" issue.
- Compliance content: curated NIST 800-53 Rev 5 control catalog with implementation statements;
  SSP template; ISCM/ConMon strategy; roles & responsibilities; crosswalks to RAISE 2.0 (RIG),
  DoD cATO (3 (+1) pillars), NIST SSDF (800-218), eMASS, and the DoD Enterprise DevSecOps Reference
  Design; templates (POA&M, authorization decision document, security assessment plan, customer
  responsibility matrix); annotated references bibliography.
- Hardened sample workload (`sample-app/`), example IaC (`deploy/terraform/`, `deploy/k8s/`),
  policy-as-code (`policy/`), docs (`docs/`), and a `Makefile` for local runs.

### Notes
- This is a reference/template. Tailor `compliance/control-catalog/control-catalog.yaml`,
  `policy/thresholds.yaml`, the SSP, and the CRM before use; confirm all mappings against the
  controlling documents (`compliance/references.md`).

<!-- Example release entry to copy when you cut v0.1.0:
## [0.1.0] - 2026-05-12
### Added
- (feature)
### Changed
- (change)
### Fixed
- (fix; reference POA&M items closed, e.g., "Closes POA&M #42 (CVE-2024-XXXXX)")
### Security
- (security-relevant change; reference findings remediated)
-->
