# Contributing

This repo is both a **DevSecOps pipeline** and a **body-of-evidence generator** — changes go
through the same change control the pipeline documents (CM-3 / CM-5; SSDF PW.2 / PS.1).

## Workflow

1. **Branch** off `main` (no direct pushes — branch protection enforces this).
2. **Make the change** in your branch. Match the surrounding style; keep diffs focused.
3. **Run the gates locally** where you can: `make scan` (or at least `make test` + `make build`).
4. **Open a PR** using the template. Fill in the **security impact analysis** section honestly
   (does this touch the authorization boundary, data flows, ports/protocols/services, trust
   relationships, privileges, or specific controls?). Update **`CHANGELOG.md`** (this is a RAISE
   App-Owner artifact / SA-10 release record).
5. **CI must pass.** The `devsecops-pipeline` check is required: SAST, SCA, SBOM, secrets, IaC,
   container scan, DAST, STIG/SCAP, license, build/test. New Critical/High findings block the
   merge; pre-existing ones go to the POA&M.
6. **Get a Code Owner review.** `.github/CODEOWNERS` routes review to the right team
   (RMF/compliance, security engineering, platform, app). Author ≠ sole approver.
7. **Merge** (squash recommended). Tag a release (`vX.Y.Z`) when you want to cut an eMASS package.

## What needs extra care

- **`compliance/` changes** (control catalog, SSP, crosswalks, ConMon, templates) — reviewed by
  the RMF/compliance team. Don't change a control's `implementation_status` or `narrative` without
  basis; don't loosen a crosswalk claim without evidence. Keep the ⚠️ caveats — they're load-bearing.
- **`policy/` changes** (thresholds, allowed licenses, Rego, Semgrep rules, scanner config) —
  reviewed by security engineering. Loosening a gate or adding a suppression requires a documented
  justification (linked POA&M / risk-acceptance issue + approver + review-by date) — the SCA checks
  the suppression files (`policy/trivy/.trivyignore`, `.trivyignore.xml`, `.gitleaks.toml`,
  `.checkov.yaml` skip lists). Prefer fixing.
- **`.github/workflows/` changes** — reviewed by security engineering + platform. Pin new `uses:`
  to a version tag (full SHA for IL4/IL5 — see `docs/impact-level-notes.md`). Keep `permissions:`
  blocks minimal.
- **`scripts/` changes** (the evidence engine) — keep them dependency-light (PyYAML only) and
  defensive (a bad input file should degrade to a warning, not a crash — except the explicit *gate*
  subcommands, which may fail the build).
- **`sample-app/` / `deploy/` changes** — keep the container hardened (non-root, minimal,
  healthcheck, pinned base) and the IaC/manifests passing the IaC gate (they're scanned).

## Reporting vulnerabilities

See `SECURITY.md` — **do not** open a public issue for a security vulnerability.

## Tooling

- `make help` lists the targets. `make tools` prints install hints for the local scanners.
- The CI pins tool versions (and Dependabot keeps them current); local runs use whatever you have
  installed — close enough for pre-flight, CI is authoritative.
