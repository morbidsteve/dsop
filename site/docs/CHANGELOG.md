# Changelog

All notable changes to this system are recorded here. This is a **RAISE 2.0 Application-Owner
artifact** (the CHANGELOG / Release Notes — a historical record of all production changes per
version) and contributes to **SA-10** (developer configuration management — release records). One
entry per release; reference the PRs and any POA&M items closed.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/); versions follow
[SemVer](https://semver.org/). Each release tag (`vX.Y.Z`) triggers the `emass-package-release`
workflow, which builds the eMASS submission package and attaches it to the GitHub Release.

## [Unreleased]
### Changed
- Demonstration workload upgraded from a 20-line echo app to **`dsop-evidence-helper`** — a real
  Flask REST service (health/version, SHA-256/384/512 + SHA3 hashing with weak-algorithm rejection,
  UUID, length-limited echo, and an **SBOM validator** that checks a CycloneDX/SPDX document — JSON
  or YAML — against the NTIA SBOM minimum elements) with real third-party deps (Flask, gunicorn,
  PyYAML and their transitive deps), so the SBOM/SCA gates have a genuine component graph; 26 unit
  tests; container labels/metadata updated.
- Evidence-engine data-quality fixes (from validating the first live runs):
  - SARIF tool-name normalization — `Semgrep OSS`/`Semgrep CE` now correctly attributed to the
    **SAST** gate (was falling into the "other" bucket).
  - Trivy's image-level **license** output (hundreds of unactionable base-image GPL/LGPL package
    entries) is no longer ingested as findings — the dedicated `license-compliance` gate
    (CycloneDX SBOM vs `policy/allowed-licenses.yaml`) is the authoritative license signal.
  - The merged SBOM / hardware-software baseline now lists **packages/applications/OS only** —
    Syft's per-**file** image entries (thousands of `/etc/...` paths) are excluded.
  - **Control test-result logic is now realistic**: a control is `Non-Compliant` only when its
    assessing gate(s) found a **Critical**, a **High with a fix available**, or an **overdue**
    finding; otherwise (gate ran; remaining open findings are lower-severity, or High/Critical with
    no vendor fix yet — e.g. base-image OS CVEs) it is **`Compliant` with the items tracked in the
    POA&M**. (Still an automated first pass — the SCA makes the final determination.)
  - **CodeQL alerts** are pulled from GitHub code scanning into the consolidated `findings.json`
    (CodeQL runs in a separate workflow and uploads to code scanning, not to a run artifact;
    other tools' alerts are not re-pulled, to avoid double-counting).
- **Dashboard**: new **Docs tab** — the compliance docs (references, roles, SSP, ConMon strategy,
  the RMF/cATO/RAISE&nbsp;2.0/SSDF/eMASS/DevSecOps-Reference-Design crosswalks, the pipeline-gates
  reference, the eMASS runbook, getting-started, etc.) are now **rendered in the page** (markdown →
  HTML, with GFM tables) instead of only referenced as file paths; each also links to its
  GitHub-rendered view. `scripts/build_dashboard_data.py` copies them into `site/docs/` and writes
  `site/data/docs.json` on every run.
- Added a `pipeline-status` aggregate job (single required status check for branch protection).

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
