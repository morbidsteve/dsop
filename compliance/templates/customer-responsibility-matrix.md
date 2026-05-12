# Customer Responsibility Matrix (CRM) / Control Inheritance — TEMPLATE

> Documents which controls the application **inherits** from the hosting platform (the **RPOC** in
> RAISE), the **DevSecOps platform / software factory**, the **cloud service provider**, and the
> **enterprise** — and which are the application's responsibility (and which are **hybrid** — the
> provider covers part, the app covers the rest). In eMASS, mark inherited controls "Inherited" /
> "Manually Inherited" and link to the provider's package, **or** upload this CRM as an artifact.
> RAISE: the DSOP marks its controls inheritable in its RMF package (preferred) or supplies a CRM,
> and the **AO approves the inheritable controls (RMF Step 2)** as part of the DSOP→RPOC transition.

Authoritative basis: NIST SP 800-37 Rev 2 (common/inherited controls), DoD Cybersecurity
Reciprocity Playbook, the platform/CSP's own SSP & CRM, the DoD/DISA Container Hardening Process
Guide (Iron Bank inherited controls — Appendix C), the DoD Cloud Computing SRG. **Get the
provider's actual CRM** and reconcile against it — the rows below are a typical starting picture,
not a substitute.

---

## Inheritance sources for this system

| Source | What it provides | Reference (SSP / ATO / CRM) |
|---|---|---|
| **Cloud Service Provider (CSP)** | IaaS: physical/environmental, infrastructure availability, hypervisor, network fabric, encryption-at-rest infrastructure (KMS/HSM), some IAM primitives | (REPLACE — the CSP's FedRAMP/DoD PA + CRM, e.g., the relevant IL2/IL4/IL5 PA) |
| **DevSecOps platform / software factory (DSOP) — the RAISE RPOC if applicable** | The orchestrator (CNCF-conformant Kubernetes per the DoD Reference Design), the artifact registries, CI/CD platform services, runtime monitoring, the multi-tier environments, admission control (signature verification), the platform's portions of CM/AU/SC/SI | (REPLACE — the platform/RPOC's eMASS package + CRM; for RAISE, the RPOC's Authorization Decision Document) |
| **Hardened base images (Iron Bank / Repo One)** | OS-level hardening + the documented inherited security controls for the chosen base image (Container Hardening Process Guide, Appendix C) | (REPLACE — the Iron Bank image, its hardening manifest, its scan reports, its inherited-controls appendix) |
| **Enterprise services** | Enterprise IdP / DoD PKI (AC/IA — identification, authentication, MFA), centralized logging/SIEM (AU), the CSSP/SOC (IR, SI-4 monitoring, active cyber defense), enterprise vulnerability scanning, DoD perimeter (cloud access points/BCAP, SC-7) | (REPLACE — references) |
| **Organization / common control program** | PM-* program controls, PL-* policies, PS-* personnel security, AT-* training program, organization-wide risk strategy (PM-9) | (REPLACE — the common-control package) |

## Control responsibility matrix (curated subset — extend to the full baseline)

`Resp.` = Inherited (I) / Common (C) / Hybrid (H) / System (S). For Hybrid, note the split.

| Control | Title | Resp. | Provided by | Application's share (if Hybrid) | Evidence |
|---|---|---|---|---|---|
| PE-* | Physical & environmental | I | CSP / platform | — | CSP/platform CRM |
| MA-* | Maintenance | I | CSP / platform | — | platform CRM |
| MP-* | Media protection | I | CSP / platform | — | platform CRM |
| PS-* | Personnel security | C | Organization | — | common-control package |
| AT-* | Awareness & training (program) | C | Organization | Provide role-based secure-dev training & records (AT-2) | LMS records |
| PM-* | Program management | C | Organization | — | common-control package |
| AC-2 / AC-17 | Account mgmt / remote access | H | Enterprise IdP + platform | App/CI service accounts, repo RBAC, OIDC tokens, least privilege | `policy/`, `deploy/k8s/`, OpenSSF Scorecard |
| AC-3 / AC-6 | Access enforcement / least privilege | H | Platform RBAC + cloud IAM | Branch protection + CODEOWNERS, container least-privilege, Conftest/OPA, scoped CI tokens | `iac` / `container` gates |
| IA-2 / IA-5 | Identification & auth / authenticator mgmt | H | Enterprise IdP / DoD PKI | No secrets in code (secret scanning + push protection), OIDC, runtime secrets from the platform vault | `secrets` gate |
| AU-2 / AU-6 / AU-12 | Logging / review / generation | H | Centralized logging/SIEM + CSSP | App emits structured logs; CI/CD audit log; ship telemetry to the SIEM | `iac` gate, `evidence_index.json` |
| SC-7 | Boundary protection | H | DoD perimeter / cloud firewalls / WAF | K8s NetworkPolicy default-deny, security-group IaC, only required ports (PPSM) | `iac` gate |
| SC-8 / SC-13 / SC-28 | Transmission / crypto / at-rest | H | Platform TLS terminators + CSP KMS (FIPS-validated) | TLS enforcement in app/IaC, no disabled cert verification, SSE-KMS in IaC, read-only runtime | `sast` / `iac` gates |
| SI-4 | System monitoring | H | Platform monitoring + CSSP (IDS/IPS/EDR, threat hunting) | Build-system monitoring (Scorecard), telemetry to the SIEM | `supply-chain` gate |
| IR-4 / IR-6 / IR-8 | Incident handling / reporting / plan | H | Platform CSSP/SOC | App-side triage & remediation; root-cause feedback to the SDLC; report per the plan | (program IRP) |
| CP-9 / CP-2 | Backup / contingency | H | CSP backup/DR | Retain code/artifacts/evidence in Git/GHCR/Releases/(optional) immutable bucket | `iac` gate |
| CM-2/3/4/5/6/7/8/10/11 | Configuration management | H/S | Platform CM at the platform layer | App-layer CM: version-controlled IaC/Dockerfile/k8s, PR change control, the IaC/container/STIG gates, the SBOM (CM-8) | `iac`/`container`/`stig`/`sbom` gates |
| RA-3/RA-5 | Risk assessment / vuln scanning | H/S | Platform infra scanning | App scanning: SCA, container, DAST, STIG/SCAP, SAST, IaC, secrets — continuously | `sca`/`container`/`dast`/`stig`/`sast`/`iac`/`secrets` gates |
| SA-3/8/10/11/15/22 | SDLC / engineering / dev CM / dev testing / dev process / unsupported components | S | — (the application owns its SDLC) | The whole pipeline | all gates + `body-of-evidence` |
| SI-2/3/7 | Flaw remediation / malicious code / integrity | H/S | Platform anti-malware/EDR + admission control | App: scanning + Dependabot + POA&M SLAs, secrets detection, image signing + SLSA provenance + signed commits | `sca`/`container`/`secrets` gates |
| SR-2/3/4/11 | Supply chain (plan / controls / provenance / authenticity) | H/S | Iron Bank (inherited container controls) + platform registries | App: SBOM, SLSA provenance, cosign signing, pinned/approved sources, license policy, OpenSSF Scorecard; C-SCRM plan | `sbom`/`sca`/`container`/`supply-chain` gates |
| CA-2/5/6/7 | Assessment / POA&M / authorization / ConMon | S (+ delegated review) | — | The pipeline + the eMASS package + the dashboard + ConMon history; AO/SCA/RPOC-ISSM make the decisions | `body-of-evidence` |
| PL-2/PL-8 | SSP / security architecture | S | — | `compliance/ssp/system-security-plan.md`, `docs/architecture.md`, the IaC | `body-of-evidence` |

## How to complete this

1. Obtain the **provider CRM(s)** (CSP, DSOP/RPOC, Iron Bank base image, enterprise services, common-control program).
2. For every control in your selected baseline, set `Resp.` and (for Hybrid) the split, and cite the provider's evidence + your evidence.
3. In eMASS, mark inherited controls "Inherited"/"Manually Inherited" and link the provider package, or attach this CRM as an artifact.
4. Re-confirm at each annual/quarterly review — if a provider loses an authorization or changes scope, the inheritance changes (RAISE: an RPOC component losing its ATO triggers RPOC re-evaluation).
