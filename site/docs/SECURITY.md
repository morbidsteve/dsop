# Security Policy

This is the **vulnerability disclosure policy** for this repository — required by NIST SSDF
**RV.1.3** (have a vulnerability disclosure policy and process), supports NIST 800-53 **SI-5 / IR-6**,
and is referenced by the issue-template config.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Instead:

- Use **GitHub Private Vulnerability Reporting** (this repo's *Security* tab → *Report a vulnerability*), or
- Email **(REPLACE — your security contact / team mailbox)**, or
- (For DoD systems) follow your component's vulnerability-reporting process and notify the **ISSM** and the platform/RPOC **CSSP/SOC**.

Please include: affected component/version, a description, reproduction steps or a proof of concept,
and the impact you observed. We will acknowledge within **(REPLACE — e.g., 3 business days)** and
provide a remediation timeline consistent with the SLAs in `policy/thresholds.yaml`
(default: Critical/High = 21 calendar days).

## Scope

This policy covers the code, container image, IaC, and CI/CD pipeline in this repository. Issues in
**inherited/common** components (the cloud provider, the DevSecOps platform / RPOC, the Iron Bank
base image, enterprise services) should also be reported to the respective provider's vulnerability
channel — see `compliance/templates/customer-responsibility-matrix.md`.

## What happens next

1. We confirm and triage the report (severity, exploitability).
2. We open a tracked **POA&M item** (or the pipeline auto-generates one if it's a scanner-visible
   finding) with a scheduled completion date per the remediation SLA.
3. We remediate (patch/upgrade/mitigate), verify on the next pipeline run, and — for DoD systems —
   notify the ISSM/AO and update eMASS as needed. For RAISE-incorporated apps, a production workload
   with an unremediated High+ finding past the 21-day window is isolated/removed pending an AO
   exception.
4. We coordinate disclosure timing with you and credit you if you wish.

## Supported versions

(REPLACE) State which versions/branches receive security fixes (e.g., the latest released `vX.Y`
line and `main`). Unsupported/end-of-life dependencies are surfaced by the SBOM + SCA tooling and
tracked under SA-22.

## Our security practices

This repository's own security posture is continuously assessed by the DevSecOps pipeline (SAST,
SCA, SBOM, secrets scanning, IaC scanning, container scanning + signing + SLSA provenance, DAST,
STIG/SCAP, license policy, OpenSSF Scorecard) — see `docs/pipeline-gates.md` and the published
dashboard. Branch protection, required Code Owner review, signed commits, and Dependabot are in
effect. See `compliance/crosswalks/ssdf-800-218-crosswalk.md` for the full SSDF mapping.
