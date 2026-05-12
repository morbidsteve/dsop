# DoD Enterprise DevSecOps lifecycle & control gates ↔ this repository — crosswalk

Maps the **DoD Enterprise DevSecOps Reference Design** family + **DevSecOps Fundamentals** (10-phase
lifecycle) + the **DevSecOps Activities & Tools Guidebook** (per-phase activities, control gates) to
this GitHub-native pipeline. Adoption of an *approved* Reference Design is **cATO pillar 3** and a
**RAISE 2.0 assumption** (an RPOC provides the Reference-Design layers).

> ⚠️ This repo is the **pipeline & evidence engine** that runs on / feeds a software factory — it is
> not itself a DSOP/software factory or an approved Reference Design. The dev/test/staging
> environments, the orchestrator, the hardened-container service, and the cloud are the platform's.
> Confirm against the current DoD CIO documents (`dodcio.defense.gov/library`): the Reference Design
> for your platform (CNCF Kubernetes / Multi-Cluster Kubernetes / AWS Managed Services / etc.),
> DevSecOps Fundamentals (e.g., v2.5), and the Activities & Tools Guidebook (e.g., v2.5).

---

## DevSecOps lifecycle phases → pipeline activities & gates

| DoD DevSecOps phase | Activities (per the Activities & Tools Guidebook themes) | This repo |
|---|---|---|
| **Plan** | Requirements, threat modeling, security requirements, criticality analysis | `docs/architecture.md` + SSP architecture section (threat model); `compliance/control-catalog/control-catalog.yaml` + `policy/thresholds.yaml` (security requirements as code); SA-15(3) criticality analysis. GitHub Issues/Projects for backlog. |
| **Develop** | Secure coding, peer review, IDE/SCM security, secrets hygiene | Git + branch protection + signed commits + CODEOWNERS review; `policy/semgrep/dod-secure-coding.yml` (secure-coding standard); pre-merge secret scanning + push protection. |
| **Build** | Compile/package securely; **SAST**; **SCA**; **SBOM**; license analysis; IaC/CaC scan; build provenance; sign artifacts; store in artifact repo | `build-test` (build + unit tests + coverage); `sast` (CodeQL + Semgrep); `sca` (Trivy fs / Grype / Dependency-Check); `sbom` (Syft → SPDX + CycloneDX); `license`; `iac` (Checkov/KICS/Trivy-config/kube-linter/Conftest); `container` (build → image scan → Hadolint/Dockle → image SBOM → cosign sign → SLSA provenance → push to GHCR). **Control gates** = `policy/thresholds.yaml`. |
| **Test** | **DAST**; IAST/fuzzing (optional); pen testing; functional/security test coverage; **STIG/SCAP compliance**; container scan re-check | `dast` (OWASP ZAP baseline against the running image); `stig` (OpenSCAP — DISA Container Platform SRG / Kubernetes STIG; supply your SCAP content); `build-test` coverage; pen testing at the AO-defined cadence (CA-8). |
| **Release** | Package the product; create documentation; sign release; release approval/gate | Tag a release → `emass-package-release.yml` builds the eMASS package + attaches it to the GitHub Release; CHANGELOG/release notes (RAISE App-Owner artifact); release gated on the BoE being current + Code Owner approval (the **ISSM-review** checkpoint — RAISE Gate 6). |
| **Deliver** | Make the product available to the operational environment (the artifact release repository) | Signed image in **GHCR** (RAISE Gates 7 & 8); only signed images deployable (admission control — RPOC-enforced). |
| **Deploy** | Install/configure in the operational environment; admission control; config drift detection | `deploy/k8s/` (hardened manifests, "restricted" Pod Security, NetworkPolicy default-deny) + `deploy/terraform/` (secure-by-default IaC); the platform/RPOC performs the actual deploy + signature verification. |
| **Operate** | Run the product; runtime hardening; least privilege | The hardened container (non-root, read-only fs, dropped caps) + the orchestrator's runtime controls (platform-provided). |
| **Monitor** | Observe/measure/monitor; runtime vulnerability scanning; log analysis; intrusion detection; supply-chain hygiene | `supply-chain` (OpenSSF Scorecard); the daily-schedule pipeline runs (continuous re-assessment); the platform/RPOC provides runtime scanning + SIEM + IDS/IPS (inherited — and the basis for cATO's "active cyber defense" pillar, which is operations-side). |
| **Feedback** | Transmit observed behavior & desired changes into the next iteration | Findings → POA&M → Dependabot/PRs → re-assessment; the ConMon trend (`conmon_history.json`) + the dashboard + the ATO Status issue; recurring patterns drive new Semgrep rules / `policy/` updates / control-catalog updates. |

**Cross-cutting "continuous" activity sets** (per the Guidebook): **Continuous Security** = every
security gate above + the BoE assembly; **Continuous Test** = `build-test` + `dast` + the gate
re-checks; **Continuous Configuration Management** = the version-controlled IaC/Dockerfile/k8s +
the change-control workflow (CM-2/CM-3/CM-5) + drift detection.

---

## "Software factory" / Reference-Design layering ↔ what this repo owns

| Reference-Design layer | Owner | This repo's relationship |
|---|---|---|
| **Infrastructure** (cloud / hardware / network — the IaaS) | CSP / platform | Inherited/common controls; `deploy/terraform/` shows the app-owned infra slice (buckets/KMS) as an example |
| **Platform / Software Factory** (the DSOP: orchestrator, CI/CD platform, hardened-container service, artifact repos, dev/test/staging environments) | DSOP owner / RPOC | This repo's pipeline runs *on* GitHub Actions and *targets* the platform; the platform provides the multi-tier environments, the orchestrator, the registry's runtime guarantees, hardened base images (Iron Bank/Repo One). |
| **Application(s)** (the workload + its CI/CD pipeline definition + its config) | Application Owner | **This repository** — the app source, the pipeline (`.github/workflows/`), the deploy artifacts (`deploy/`), the policy-as-code (`policy/`), and the compliance content (`compliance/`). |
| **Reference Design Interconnects** (the boundaries between layers — where tailoring is allowed without breaking core software-factory capabilities) | shared | Documented in the Customer Responsibility Matrix (`compliance/templates/customer-responsibility-matrix.md`) and the SSP's boundary section. |

---

## Hardened containers / Iron Bank

The DoD/DISA **Container Hardening Process Guide** (V1R2, Aug 2022) defines **DoD Hardened
Containers** published to **Iron Bank** (`registry1.dso.mil/ironbank/...`) via **Repo One**
(`repo1.dso.mil`), with documented **inherited security controls** for consuming programs. This
repo's Dockerfile uses `python:3.12-slim` as a portable default but **recommends** swapping to an
Iron Bank base image (by digest) for DoD use — `policy/opa/container_image.rego` emits a warning to
that effect. When you do: cite the Iron Bank image + its hardening-manifest/scan reports + the
inherited-controls appendix in your SSP/CRM, and the `stig` gate's burden shrinks (much of the OS
hardening is inherited). The `container` gate (Trivy/Grype/Hadolint/Dockle) still runs as
defense-in-depth and to cover *your* layers on top of the base.

---

## Approved Reference Design / "Pathway to a Reference Design"

If your platform isn't already an approved Reference Design, the DoD CIO **"Pathway to a Reference
Design"** process lets a new architecture be submitted for evaluation. This repo doesn't change
that — but it gives the platform team a concrete, transparent **pipeline + control-gate + evidence**
implementation to point at when describing the "Application" layer's security capabilities in the
submission, and a working example of the continuous-evidence collection a cATO assessment expects.
