# Getting started — adopt this template for a real program

## 0. Prerequisites

- A GitHub organization (GitHub Enterprise Cloud for IL2; GitHub Enterprise Server for IL4/IL5 — see `impact-level-notes.md`).
- GitHub Advanced Security (for CodeQL default setup, secret scanning + push protection, code scanning) — or use the in-repo `codeql.yml` and the OSS scanners (this repo works without GHAS, just with fewer native features).
- Permissions to enable GitHub Pages, Actions, Dependabot, and to configure branch protection.

## 1. Create your repo from this template

- GitHub UI → "Use this template" → create your repo. (Or clone and push.)
- The repo name matters: the dashboard publishes to `https://<org>.github.io/<repo>/`, and the
  container image pushes to `ghcr.io/<org>/<repo>/sample-app`.

## 2. Enable the GitHub features

- **Settings → Pages → Source: "GitHub Actions"** (the pipeline publishes the dashboard via `actions/deploy-pages`).
- **Settings → Actions → General:** allow Actions; allow GHCR package writes; require approval for fork PRs.
- **Settings → Code security:** enable Dependabot alerts + security updates + version updates (the `dependabot.yml` config), the dependency graph, secret scanning + **push protection**, and (if licensed) CodeQL default setup *or* keep the `codeql.yml` workflow.
- **Settings → Branches → branch protection on `main`:** require pull requests, require review **from Code Owners**, require the `devsecops-pipeline` status check to pass, require signed commits, dismiss stale approvals, restrict who can push. (This is your CM-3 / CM-5 evidence.)
- **Update `.github/CODEOWNERS`:** replace the `@your-org/...` placeholder teams with your real GitHub teams (RMF team, security engineering, platform team, app team).
- (Optional) **Settings → Pages → enforce HTTPS**; restrict Pages visibility to org members if needed.

## 3. Tailor the compliance content

In rough priority order:

1. `compliance/control-catalog/control-catalog.yaml` — replace every `(REPLACE …)` in `metadata`; tailor each control's `narrative` to your actual implementation; **add the full applicable NIST 800-53 Rev 5 baseline** (this file is a curated subset) with implementation statements / inheritance / NA determinations; apply your CNSSI 1253 categorization, overlays, and the DoD-specific assignment values from the RMF Knowledge Service; reconcile the `ccis:` against the authoritative DoD CCI list.
2. `policy/thresholds.yaml` — set the build-blocking gates and the remediation SLAs to your AO's risk tolerance (the defaults align to the RAISE 21-day rule and a Moderate residual-risk ceiling). Start with `enforce: false` if you have a big initial backlog, get it into the POA&M, then flip to `true`.
3. `compliance/ssp/system-security-plan.md` — system description, authorization boundary, categorization, interconnections, PPSM, roles.
4. `compliance/templates/customer-responsibility-matrix.md` — reconcile against the actual CRMs from your CSP, your DevSecOps platform / RPOC, your Iron Bank base image, and your enterprise/common-control programs.
5. `compliance/conmon/continuous-monitoring-strategy.md` — frequencies, SLAs (mirror `thresholds.yaml`), reporting cadence, edge-ops.
6. `compliance/references.md` — re-verify each document's current version; add dated verification notes.
7. `docs/architecture.md` — replace the sample diagrams with your workload's real architecture / data flows (a RAISE App-Owner artifact).
8. `policy/` — tune `allowed-licenses.yaml`, `.gitleaks.toml`, `trivy.yaml`/`.trivyignore`, `.checkov.yaml`, `dod-secure-coding.yml` (add your secure-coding standard as Semgrep rules), `zap/rules.tsv`, and the `opa/*.rego` policies to your environment.

## 4. Replace the workload

- Replace `sample-app/` with your application (or multiple services). Keep the principles: hardened multi-stage Dockerfile (non-root, minimal, healthcheck, pinned base — prefer an Iron Bank image by digest), unit tests + coverage, secure-by-default config. Update `compliance/control-catalog.yaml > metadata.IMAGE_NAME` references and the workflow `env.IMAGE_NAME` if you rename.
- Update `.github/workflows/devsecops-pipeline.yml`: the `build-test` job's language/build steps; the `codeql.yml` `language` matrix; the `dependabot.yml` ecosystems/directories; the `container` job's `context`/`file`.
- Replace `deploy/terraform/` and `deploy/k8s/` with your real IaC/manifests (keep them passing the IaC gate — they're scanned).

## 5. Push and verify

- Push to `main` (or open a PR). The `devsecops-pipeline` runs all gates → `body-of-evidence` assembles `evidence/` → `publish-dashboard` deploys to GitHub Pages.
- Check the dashboard at `https://<org>.github.io/<repo>/`.
- Check the auto-created **"ATO Status"** issue (the `ato-status-report` workflow runs after the pipeline + weekly; you can also `workflow_dispatch` it).
- Download the `body-of-evidence` workflow artifact to inspect `evidence/`.

## 6. Cut an eMASS package

- Tag a release: `git tag v0.1.0 && git push --tags` (or use the GitHub Releases UI). This triggers `emass-package-release.yml`, which builds the eMASS submission package and attaches `emass-package.zip` (+ the summary, POA&M, and controls CSVs) to the GitHub Release.
- Then follow `docs/emass-submission-runbook.md`.

## 7. Operate it (RAISE / cATO)

- Keep the pipeline green and running daily (it does, via the `schedule:` cron).
- Close POA&M items within SLA; use the POA&M / risk-acceptance / ATO-milestone issue templates.
- For RAISE: provide the App-Owner artifacts (see `compliance/crosswalks/raise-2.0-crosswalk.md` §B), give the RPOC ISSM the eMASS-package link and the dashboard, send mitigation statements before each release, and bring the package to the quarterly review (the SCA signs the SAR; the AO sets the next review date).
- For cATO: also document the active-cyber-defense pillar from your CSSP/SOC, cite your approved DevSecOps Reference Design, and route the BoE through the AO + Component CISO to the DoD CISO. (See `compliance/crosswalks/cato-evaluation-crosswalk.md`.)

## Local development

- `make scan` runs (most of) the gates locally the way CI does (needs Docker + the listed tools — `make tools` prints install hints).
- `make test` runs the unit tests; `make build` builds the container; `make evidence` runs the aggregation scripts over a `raw-evidence/` directory you populate.
- `make site` regenerates the dashboard data and serves `site/` locally for preview.
