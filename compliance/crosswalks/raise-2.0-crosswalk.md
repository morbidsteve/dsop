# Navy RAISE 2.0 ↔ this repository — crosswalk

Maps the **Rapid Assess and Incorporate Software Engineering (RAISE) 2.0 Implementation Guide
("RIG"), Version 1.0 (4 Oct 2022)** to what this DevSecOps pipeline produces. RAISE 2.0 lets a
**containerized application** be **incorporated into the existing ATO of an authorized DevSecOps
platform** (a **RAISE Platform of Choice / RPOC**) instead of obtaining its own ATO — via control
inheritance + a Customer Responsibility Matrix, with the AO **delegating assessment authority to
the RPOC ISSM**, continuous pipeline evidence, **quarterly reviews** with the SCA/AO, and an
**annual AO review of the RPOC**.

> ⚠️ **Confirm against the current RIG.** This is built from the public RIG v1.0; DON has signaled
> future updates. Some RIG annexes/templates and the Navy RMF Process Guide referenced in RIG
> Appendix D may be CAC-restricted. Two known nuances: (a) RIG v1.0 does **not** name IaC scanning
> or a standalone OSS-license gate as Security Gates — this repo runs them anyway as expected
> practice; (b) RIG v1.0 does **not** separately define ISSO/ISSE roles (it uses CIO/SISO, AO,
> SCA, **Technical Authority (TA)**, **RPOC Owner**, **RPOC ISSM**, **Application Owner**).

---

## A. The 8 RAISE Security Gates (RIG Table 5) → pipeline

| RAISE Gate | Requirement | This pipeline | Where | Evidence artifact |
|---|---|---|---|---|
| **Gate 1** | **SAST** for available source code (not required for COTS) | `sast` (CodeQL + Semgrep + custom DoD secure-coding rules) + `codeql.yml` | `.github/workflows/devsecops-pipeline.yml` (`sast-semgrep`), `.github/workflows/codeql.yml` | GitHub code scanning; `evidence/sast/**`; `*.sarif` |
| **Gate 2** | **Dependency list / SBOM** | `sbom` (Syft → SPDX 2.3 + CycloneDX 1.5, source & image), `sca` (Trivy fs / Grype / OWASP Dependency-Check), `license` (OSS policy) | `devsecops-pipeline.yml` (`sbom-source`, `sca-dependencies`, `license-compliance`, and the image SBOM in `container`) | `evidence/sbom/**`, `evidence/sca/**`, `evidence/license/**`; SBOM as Release asset + cosign attestation |
| **Gate 3** | **Secrets / keys detection** | `secrets` (Gitleaks + TruffleHog) + GitHub secret scanning & **push protection** + Trivy/Semgrep secret rules | `devsecops-pipeline.yml` (`secrets-scan`); repo Security settings | `evidence/secrets/**` |
| **Gate 4** | **Container Security Scanning (CSS)** | `container` (Trivy + Grype image scan + Hadolint + Dockle hardening lint) | `devsecops-pipeline.yml` (`container`) | `evidence/container/**` |
| **Gate 5** | **DAST** | `dast` (OWASP ZAP baseline against the running image) | `devsecops-pipeline.yml` (`dast`) | `evidence/dast/**` |
| **Gate 6** | A step that **allows the RPOC ISSM to review** | Branch protection + required Code Owner review (CODEOWNERS) on every change; the auto-maintained **"ATO Status" issue**; the GitHub Pages **AO/ISSM dashboard**; releases gated on the BoE being current | `.github/CODEOWNERS`, `pull_request_template.md`, `.github/workflows/ato-status-report.yml`, `site/` | PR review history; ATO Status issue; dashboard |
| **Gate 7** | **Sign the release container image** | `cosign sign` (keyless/Sigstore, Rekor-logged) + **SLSA build provenance** attestation (`actions/attest-build-provenance`) + CycloneDX SBOM attestation | `devsecops-pipeline.yml` (`container`) | image signature + provenance in GHCR; `evidence/provenance/**` |
| **Gate 8** | **Store the release container image in an artifact repository** | Push to **GHCR** (`ghcr.io/<org>/<repo>/sample-app:sha-<...>`); only signed images deployable (admission control — RPOC-enforced) | `devsecops-pipeline.yml` (`container` → `Push image`) | image digest in `evidence_index.json` / Release notes |

Every release-candidate container **must pass the full pipeline** before it can reach the artifact
release repository, and **only signed images may be deployed** (RPOC admission control) — matching
RPOC requirements 14, 22, and 23.

**Beyond the 8 named gates (expected practice / defense-in-depth):** IaC/config scanning
(`iac`: Checkov, KICS, Trivy-config, kube-linter, Conftest/OPA), STIG/SCAP evaluation (`stig`:
OpenSCAP — DISA Container Platform SRG / Kubernetes STIG), supply-chain hygiene (`supply-chain`:
OpenSSF Scorecard), and unit testing + coverage (`build-test`).

---

## B. Application-Owner artifacts (RIG Table 4 / Appendix C SLA) → this repo

The RAISE Application Owner must produce and maintain these; this repo provides each (or a clearly
labeled place for it):

| RAISE App-Owner artifact | Here |
|---|---|
| **Vulnerability Management Plan** | `compliance/conmon/continuous-monitoring-strategy.md` (vuln-management section) + `policy/thresholds.yaml` (SLAs) — extend into a standalone plan if your RPOC requires it |
| **Application Architecture diagram** (components, user connections, data flows, external connections) | `docs/architecture.md` + the SSP architecture section + IaC (`sample-app/Dockerfile`, `deploy/k8s/`, `deploy/terraform/`) |
| **README** (how to build/test locally) | `README.md` + `docs/getting-started.md` + `Makefile` (`make scan` runs the gates locally) + `sample-app/` |
| **CHANGELOG / Release Notes** (historical record of all production changes per version) | `CHANGELOG.md` (required by the PR template; SA-10) + GitHub Releases (per tag, with the eMASS package attached) |
| **Aggregated scan results** — SAST, DAST, Container Security, Dependencies/SBOM | `evidence/sast/**`, `evidence/dast/**`, `evidence/container/**`, `evidence/sca/**` + `evidence/sbom/**`; normalized & deduplicated in `evidence/findings.json`; viewable on the dashboard |
| **Mitigation statements** for all open vulnerabilities (per the SCA Risk Assessment Guide) | `evidence/boe/poam.csv`/`.json` (each item has `mitigations`, `residual_risk_level`, `comments`); supplement per-finding statements via the POA&M issue template; provided to the RPOC ISSM before each release and at quarterly reviews |
| **SRG + STIG for the application** (continuously maintained) | `stig` gate (OpenSCAP) produces results + a `.ckl` skeleton — **supply your applicable DISA SRG/STIG SCAP content** from the DoD Cyber Exchange (see `docs/pipeline-gates.md` #stig); track open findings in the POA&M |
| **Security Categorization Form (SCF)** / **Privacy Impact Assessment (PIA)** | Capture in `compliance/ssp/system-security-plan.md` (categorization & privacy sections); attach the official SCF/PIA forms as Artifacts in the eMASS package |
| **DADMS ID + DITPR-DON ID** (or higher-classification equivalents) | `compliance/control-catalog/control-catalog.yaml > metadata` (and surfaced in `evidence/emass-package/MANIFEST.json > system`) |
| **Signed SLA with the RPOC Owner** | Out of repo scope (signed agreement) — reference it in the SSP; the repo's pipeline/SLAs (`policy/thresholds.yaml`) should reflect the SLA terms |
| **Release Plan** (deployment frequency/process) | `docs/getting-started.md` (release process) + the `emass-package-release.yml` tag workflow + CHANGELOG cadence |

---

## C. RPOC requirements (RIG Table 2, the 24 "RPOC #" items) — who provides what

These are **RPOC** (platform) obligations, not the application's. They're listed here so you can
see which the application's pipeline supports vs. which the RPOC must provide (and which the
application *inherits* from the RPOC's ATO). Map each to the Customer Responsibility Matrix.

| RPOC # | Requirement | Provided by | This repo's relationship |
|---|---|---|---|
| 1 | Current ATO | **RPOC** | Application is incorporated into this ATO (inherited) |
| 2, 3 | Host & orchestrate containerized apps | **RPOC** | Deploy targets (`deploy/k8s/`) assume this |
| 4 | Support Continuous Monitoring | **RPOC** + app | App contributes the pipeline ConMon (CA-7) and the dashboard/ConMon history; runtime/infra ConMon is RPOC |
| **5, 20, 22** | Execute the Security Gates / pipeline meets the gates / every release-candidate passes the pipeline | **RPOC** (operates the pipeline) — here the **app's own GitHub-native pipeline** implements all 8 gates | Section A above |
| 6 | Maintain a POA&M for the RPOC **and** the apps | **RPOC** + app | App auto-generates its POA&M (`evidence/boe/poam.csv`); RPOC consolidates |
| 7 | Support quarterly review with SCA/AO | **RPOC** | App provides the QREV deliverables (Section D) |
| 8 | All CI/CD pipeline tools TA-certified | **RPOC** (TA certifies) | Tool list is explicit in `.github/workflows/` and `policy/` for the TA to assess (DevSecOps CI/CD Assessment Guidebook) |
| 9 | Keep the RPOC RMF package current | **RPOC** | App's `eMASS` package feeds the RPOC package deltas |
| 10 | Maintain SLAs with App Owners | **RPOC** + app | `policy/thresholds.yaml` encodes the app side of the SLA |
| 11, 24 | Provide cybersecurity dashboards / vuln reports for auditing & for App-Owner review | **RPOC** — here the app *also* publishes its own GitHub Pages dashboard + ATO Status issue | `site/`, `ato-status-report.yml` |
| 12, 13 | Provide container & code repositories | **RPOC** (and/or GitHub) | This repo (code) + GHCR (containers) |
| 14, 19 | Container signing & verification / ongoing vuln scans on all running containers | **RPOC** (admission control + runtime scanning) | App signs at build (Gate 7); RPOC verifies at admission & rescans at runtime |
| 15 | Retain every currently-deployed image | **RPOC** | App pushes/retains build images in GHCR; RPOC retains deployed images |
| 16 | Support pen testing as the AO requests | **RPOC** + app | App's DAST gate is continuous; full pen tests on AO request → POA&M |
| 17 | Provide CI/CD pipeline tools | **RPOC** — here GitHub Actions + the actions in `.github/workflows/` | (the pipeline) |
| 18, 23 | Host apps only at/below their approved categorization; don't deploy apps that fail SLA | **RPOC** | Categorization in `control-catalog.yaml > metadata`; SLA in `policy/thresholds.yaml` |
| 21 | Define the application deployment process(es) | **RPOC ISSM** | `deploy/` + `docs/getting-started.md` describe the app's deploy artifacts |

> **Note:** This repository is **not itself an RPOC.** Becoming an RPOC requires the platform's AO
> to approve the platform's inheritable controls (RMF Step 2) **and** the **Technical Authority**
> to certify the platform's CI/CD pipeline tools (per the DevSecOps CI/CD Assessment Guidebook),
> after which the AO updates the platform's **Authorization Decision Document** to confer RPOC
> status (RIG §4.3). This repo helps an *application* be incorporated into an RPOC's ATO via RAISE
> 2.0. If you are building the *platform*, the relevant artifacts here are the gate definitions,
> the inheritable-controls posture, and the CI/CD tool list for the TA to assess; also see
> `compliance/templates/customer-responsibility-matrix.md` and the example CI/CD-tools
> certification-request structure described in RIG Appendix D.

---

## D. Quarterly review (QREV) deliverables (RIG Table 3) → this repo

At each RAISE quarterly review the RPOC brings the items below; the application contributes its
share (the SCA reviews the RPOC RMF-package deltas and signs the SAR before the AO meeting; the AO
sets the next review date).

| QREV item (RIG Table 3) | Application contribution from this repo |
|---|---|
| 1. Security Plan (software list, RPOC architecture diagrams, **PPSM**) | App SW list = `evidence/sbom/components.json` / `emass-package/hardware-software-list.csv`; app architecture = `docs/architecture.md`; app PPSM = `emass-package/ppsm.csv` (populate from the SSP) |
| 2. Security Assessment Plan (SAP) | `compliance/templates/security-assessment-plan.md` (the app's testing/assessment plan = the pipeline gates) |
| 3. Privacy Impact Assessment (PIA) | SSP privacy section + the official PIA form (attach as an Artifact) |
| 4. POA&M and corresponding security controls | `evidence/boe/poam.csv` + `evidence/boe/controls.json` (in `emass-package/`) |
| 5. Report of newly deployed/removed applications | CHANGELOG.md + GitHub Releases (the app's deployment history) |
| 6. Consolidated vulnerabilities report | `evidence/findings.json` + the dashboard's Findings view + per-gate reports under `evidence/<gate>/**` |
| 7. Application Deployment Artifacts: SRG & STIG, SAST report, DAST report, Container Security Scan report, Dependency Report / SBOM | `evidence/stig/**` (+ `.ckl`), `evidence/sast/**`, `evidence/dast/**`, `evidence/container/**`, `evidence/sca/**` + `evidence/sbom/**` — all bundled in `evidence/emass-package/artifacts/<gate>/` with a manifest mapping each to controls/CCIs |

The **eMASS submission package** (`emass-package.zip`, attached to each version-tag Release, and
the `body-of-evidence`/`emass-package` workflow artifacts on every run) is, in effect, the
application's RAISE quarterly-review packet — give the link to the RPOC ISSM.

---

## E. Residual risk, remediation timelines, validation

| RAISE rule (RIG) | This repo |
|---|---|
| Application findings/vulns must be **mitigated to residual risk not exceeding Moderate**; **High-risk applications are out of scope** of RAISE (escalate via the AO) | `policy/thresholds.yaml > poam.raise_residual_risk_ceiling: moderate`; `generate_poam.py` flags items whose residual risk exceeds the ceiling as **"out of RAISE scope — AO escalation required"**; the dashboard & ATO Status issue surface them |
| Newly discovered **raw "High" and above in production** remediated/mitigated within **21 calendar days**; else the RPOC ISSM (with the App Owner) **isolates/removes** the offending workloads; exceptions require AO notification | `policy/thresholds.yaml > poam.sla_days: {critical: 21, high: 21, medium: 90, low: 365}`; `generate_poam.py` computes `Scheduled Completion Date = first_seen + sla_days[severity]` and sets an **overdue** flag; the ConMon trend tracks mean-time-to-patch; overdue items are escalated on the dashboard / ATO Status issue / via the control-deviation (risk-acceptance) issue template |
| High+ mitigations reviewed by the **RPOC Qualified Validator / Independent Assessor** | The POA&M items are produced for that review; record the validator's disposition in the POA&M comments / the risk-acceptance issue |
| **Edge / disconnected** environments (ships, subs, planes, tactical, air-gapped): if the production edge node can't do ConMon, the ConMon requirement is met at the **Staging/Pre-Prod** environment, and the edge node **syncs** with Stage as the mission allows | Run the full pipeline + ConMon against the Staging tier; document the edge-sync process in the ConMon strategy; for IL4/IL5/air-gapped, see `docs/impact-level-notes.md` (internal mirrors, self-hosted runners) |

---

## F. RAISE roles ↔ this repo

| RAISE role (RIG Table 1) | What they do | Touchpoints here |
|---|---|---|
| **CIO / SISO** | Owns RMF within the DoD Component cyber program | (org-level) |
| **Authorizing Official (AO)** | Ensures the RPOC meets acceptable residual-risk criteria; **issues the authorization**; delegates assessment authority to the RPOC ISSM; runs quarterly/annual reviews; approves pen-test requests & exceptions | The **AO dashboard** (`site/`), the **ATO Status** issue, `compliance/templates/authorization-decision-document.md`, the control-deviation/risk-acceptance issue template |
| **Security Control Assessor (SCA)** | Reviews containerized apps since the last review; **signs the SAR** | `evidence/emass-package/` (controls + test results + POA&M + artifacts), `compliance/templates/security-assessment-plan.md` |
| **Technical Authority (TA)** | **Certifies the RPOC's CI/CD pipeline tools** for usability/functional capability | Tool list in `.github/workflows/` + `policy/` (transparent for assessment) |
| **RPOC Owner** | Overall state of the RPOC | (platform-side) |
| **RPOC ISSM** | Cybersecurity of the RPOC; supports AO/SCA reviews; the **delegated decision-maker**; decides app fit; defines deployment process(es); monitors pipelines; reviews High+ mitigations; enforces signed-image-only admission; records who implements the pipeline in the SLA | Gate 6 review (CODEOWNERS/PR), the dashboard, `evidence/boe/poam.csv` (High+ items), `deploy/` |
| **Application Owner** | Responsible for the **entire SDLC**; the DevSecOps team + program office; produces the App-Owner artifacts (Section B); signs the SLA | This whole repository |

(If your program also uses **ISSO/ISSE** titles: ISSO ≈ app-side support to the RPOC ISSM / part
of the Application Owner team; ISSE ≈ security engineering within the App-Owner DevSecOps team or
the RPOC engineering team. See `compliance/roles-and-responsibilities.md`.)

---

## G. RAISE ↔ RMF / cATO / DevSecOps Reference Design / eMASS (one paragraph)

RAISE 2.0 is a **tailoring of RMF (DoDI 8510.01)** — not a replacement: it keeps RMF roles and the
RMF steps but eliminates the per-app ATO for in-scope containerized apps via control inheritance +
CRM and delegates assessment to the RPOC ISSM. It **assumes the platform provides the layers of the
DoD Enterprise DevSecOps Reference Design** and points to the DoD DevSecOps Fundamentals for ConMon
definitions; an RPOC is essentially "a DoD Enterprise DevSecOps platform put through the Navy's
RAISE designation process." Its mechanics (active ConMon strategy, near-real-time dashboards,
periodic AO reviews, an authorized environment carrying the authorization) are **cATO-aligned**,
though RIG v1.0 doesn't claim full conformance with the DoD cATO Evaluation Criteria (notably the
"active cyber defense" pillar — see `cato-evaluation-crosswalk.md`). The **RPOC's RMF package lives
in eMASS** (MCAST for the Marine Corps), apps register in **DADMS** and **DITPR-DON**, and CI/CD
release results + mitigation statements are uploaded into the RMF tool so the ISSM/SCA/AO get
near-real-time risk information via dashboard/API — which is exactly what the `evidence/emass-package/`
output and the GitHub Pages dashboard provide.
