# NIST SP 800-218 (SSDF v1.1) ↔ this repository — crosswalk

Maps the **Secure Software Development Framework** practices/tasks to what this pipeline does. The
SSDF is outcome-based; the implementations below are *examples that satisfy the outcome* — adapt to
your environment. This crosswalk also supports the **CISA Secure Software Development Attestation
Form** (OMB M-22-18 / M-23-16) if your software is delivered to a federal agency, and EO 14028 §4e.

> ⚠️ Confirm against NIST SP 800-218 v1.1 (Feb 2022) and any newer revision (a v1.2 draft has been
> in comment; SP 800-218A covers GenAI). Task descriptions below are paraphrases.

## PO — Prepare the Organization

| Practice | This repo |
|---|---|
| **PO.1** Define security requirements (dev infrastructure & software; communicate to third parties) | Security requirements as code: `policy/thresholds.yaml` (gates/SLAs), `policy/semgrep/dod-secure-coding.yml` (secure-coding standard), `compliance/control-catalog/control-catalog.yaml` (control requirements), `compliance/references.md` (the governing framework requirements). PO.1.3 (require SBOM/provenance/attestation from suppliers): document supplier requirements in your C-SCRM plan (SR-2) and intake vendor SBOMs/attestations into the SBOM/HW-SW baseline. |
| **PO.2** Roles & responsibilities; role-based training; management/AO commitment | `compliance/roles-and-responsibilities.md`; `.github/CODEOWNERS`; training records are program-provided (AT-2 — PO.2.2); management/AO commitment is the authorization decision (CA-6 — PO.2.3). |
| **PO.3** Implement supporting toolchains; follow recommended toolchain security; configure tools to generate evidence | The toolchain is explicit in `.github/workflows/` and `policy/`; OpenSSF Scorecard checks toolchain hygiene (Dangerous-Workflow, Token-Permissions, Pinned-Dependencies); every gate is configured to emit machine-readable artifacts (SARIF/JSON), which `scripts/aggregate_evidence.py` collects as evidence of the toolchain's support of secure practices. |
| **PO.4** Define & use criteria for software security checks; gather/safeguard the data | `policy/thresholds.yaml` defines the criteria (pass/fail per check) and the POA&M thresholds; the `body-of-evidence` job gathers all check data, normalizes it, and stores it as durable artifacts/Release assets (and the ConMon history). |
| **PO.5** Secure development environments (separate/protect each; secure dev endpoints) | Ephemeral GitHub-hosted (or controlled self-hosted) runners; separated environments (`deploy/` multi-tier); minimized workflow `permissions:`; no long-lived creds (OIDC); secret scanning + push protection. Developer-endpoint hardening is a program/common control — reference it. |

## PS — Protect the Software

| Practice | This repo |
|---|---|
| **PS.1** Protect all forms of code from unauthorized access/tampering | Git with branch protection, required Code Owner review, signed commits, minimized CI permissions; secrets never in code (Gitleaks/TruffleHog/push protection); access enforced via GitHub RBAC. (CM-5, AC-3, IA-5.) |
| **PS.2** Mechanism to verify release integrity | Container images signed with cosign/Sigstore (Rekor-logged); Git signed tags; Release assets with integrity hashes; SBOM attestation on the image — consumers can verify (`cosign verify`). (SI-7.) |
| **PS.3** Archive & protect each release; collect/safeguard/share **provenance** data for all components | Every release archived (Git + GHCR + GitHub Releases + optional immutable artifact bucket in `deploy/terraform`); **SLSA build-provenance attestation** (`actions/attest-build-provenance`) + the SPDX/CycloneDX SBOMs capture component provenance; these are published as Release assets and registry attestations. (SR-4, CM-8, CP-9.) — This is the core "SBOM + provenance" SSDF requirement. |

## PW — Produce Well-Secured Software

| Practice | This repo |
|---|---|
| **PW.1** Design to meet security requirements & mitigate risk (threat modeling, attack-surface mapping) | `docs/architecture.md` + the SSP architecture section (threat model / data flows / trust boundaries); design decisions recorded. (PL-8, SA-8, RA-3.) |
| **PW.2** Review the design vs. requirements/risk | Required Code Owner review on PRs; the PR template's security-impact-analysis section; design review for material changes. (CM-3/CM-4, SA-11(4).) |
| **PW.4** Reuse well-secured components instead of duplicating; acquire/maintain well-secured components; verify acquired components | SCA (Trivy/Grype/Dependency-Check) + the SBOM + license policy gate every component; pinned versions from approved sources; Dependabot keeps them current; OpenSSF Scorecard scores dependency hygiene. (CM-10, RA-5, SA-22, SR-3/6.) |
| **PW.5** Adhere to secure coding practices | `policy/semgrep/dod-secure-coding.yml` (banned crypto, no eval/exec on input, no `shell=True`, no disabled TLS verification, no debug mode, non-root Dockerfile, hard-coded-secret detection) + CodeQL `security-extended`; the sample app demonstrates secure-by-default coding. (SI-10/SI-11 themes; SA-15.) |
| **PW.6** Configure compilation/interpreter/build for executable security; document the settings | Multi-stage build leaving build tools out; pinned base image; `PYTHONDONTWRITEBYTECODE`/`PYTHONUNBUFFERED`; reproducible-build practices; the Dockerfile *is* the documented build configuration (under CM-2/CM-6). |
| **PW.7** Review and/or analyze human-readable code — **static analysis (SAST) + peer review** | `sast` gate (CodeQL + Semgrep) on every push/PR + required Code Owner review. (SA-11(1), RA-5; RAISE Gate 1.) |
| **PW.8** Test executable code — **dynamic analysis, fuzzing, pen testing** | `dast` gate (OWASP ZAP baseline) on every run; pen testing at the AO-defined frequency (CA-8); unit tests in the build gate. (SA-11(8)/(5); RAISE Gate 5.) |
| **PW.9** Configure software to have **secure settings by default** | The hardened Dockerfile (non-root, minimal, healthcheck, read-only fs at runtime), the "restricted" Kubernetes Pod Security profile + RuntimeDefault seccomp + dropped caps + NetworkPolicy default-deny (`deploy/k8s/`), secure-by-default IaC (`deploy/terraform/`), the app's debug-off + security-headers defaults — all verified by the `iac`/`container`/`stig` gates. (CM-6, CM-7, SC-7/8/28.) |

## RV — Respond to Vulnerabilities

| Practice | This repo |
|---|---|
| **RV.1** Identify & confirm vulnerabilities on an ongoing basis; have a vulnerability disclosure policy | Daily + per-change scanning (SCA/container/DAST/STIG/SAST/IaC/secrets) + Dependabot security updates + monitoring CVE feeds via the scanners' DBs; **`SECURITY.md`** is the vulnerability disclosure policy. (RA-5, SI-2; RV.1.3.) |
| **RV.2** Assess, prioritize, remediate vulnerabilities | Findings are severity-rated (CVSS-aligned), deduplicated, gated, and tracked in the **POA&M** with remediation SLAs (RAISE: High+ in prod = 21 days); risk responses (patch/mitigate/accept/advise) recorded per item; remediation verified on the next run. (CA-5, SI-2, RA-3.) |
| **RV.3** Analyze root causes; spot patterns; review for similar vulns; update the SDLC to prevent recurrence | Recorded via PR/issue history; recurring patterns should drive new Semgrep rules / `policy/` updates / control catalog updates; the ConMon trend surfaces persistent or re-opening findings. (IR-4 post-incident; SA-15 process review.) |

---

## CISA Secure Software Development Attestation Form — supporting evidence map

| Attestation element (paraphrased) | Evidence from this repo |
|---|---|
| Software developed/built in environments meeting specified requirements (separation, MFA, logging/monitoring, encryption, etc.) | PO.5 + PO.3 + PW.6 above; ephemeral runners, minimized permissions, OIDC, secret scanning, audit logging (AU-2/AU-12), SC-8/SC-28 |
| Good-faith effort to maintain trusted source-code supply chains (automated tools/processes for OSS provenance/integrity) | PW.4 + PS.3 above; SCA, SBOM, SLSA provenance, cosign signing, pinned/approved sources, OpenSSF Scorecard |
| Maintain provenance data for internal & third-party code/components to the extent feasible | PS.3.2; SLSA build provenance + SPDX/CycloneDX SBOMs (source & image) |
| Employ automated tools/processes to check for security vulnerabilities (SAST/DAST/SCA) and remediate prior to release and on an ongoing basis | PW.7/PW.8 + RV.1/RV.2 above; the full gate set + the POA&M + daily ConMon runs |

If you cannot attest to an element, file a POA&M item (the POA&M issue template / `policy/thresholds.yaml`-driven POA&M) and obtain agency approval per OMB M-23-16.
