# System Security Plan (SSP) — (REPLACE) DSOP Reference System

> **Template.** Replace every `(REPLACE …)` placeholder. This SSP is partly *self-maintaining*:
> control implementation status and narratives are kept current from
> `compliance/control-catalog/control-catalog.yaml` and the pipeline evidence
> (`evidence/boe/controls.json`), and this file is included in the eMASS submission package each
> release. Tailor to your AO's / SCA's required SSP format (many DoD components require the eMASS
> -generated SSP layout or a specific template — confirm).
>
> RMF: this is the **PL-2** artifact. NIST SP 800-37 Rev 2; NIST SP 800-18 (SSP guidance); DoDI
> 8510.01; CNSSI 1253 (categorization). See `compliance/references.md`.

---

## 1. System identification

| Field | Value |
|---|---|
| System name | (REPLACE) DSOP Reference System |
| System acronym | (REPLACE) DSOPREF |
| eMASS System ID | (REPLACE) |
| DITPR-DON ID | (REPLACE) |
| DADMS ID | (REPLACE) |
| System owner / Program Manager | (REPLACE) |
| ISSM | (REPLACE) |
| ISSO | (REPLACE) |
| ISSE / Systems Security Engineer | (REPLACE) |
| Authorizing Official (AO) / AODR | (REPLACE) |
| Security Control Assessor (SCA) | (REPLACE) |
| RAISE Platform of Choice (RPOC) this app is incorporated into (if applicable) | (REPLACE — e.g., NAVWAR/NIWC Pacific Overmatch Software Armory) |
| RPOC Owner / RPOC ISSM (if RAISE) | (REPLACE) |
| Authorization type | (REPLACE) ATO / ATO with conditions / IATT / cATO / RAISE 2.0 incorporation into the RPOC's ATO |
| Authorization status & dates | (REPLACE) |
| Operational status | (REPLACE) Operational / Under development / Major modification |

## 2. System description & purpose

(REPLACE) Describe the mission/business function the system supports, its users, and what it does.
Example skeleton: "A containerized application (or set of microservices) developed and operated
through a GitHub-native DevSecOps pipeline (this repository) and deployed onto [the RPOC / an
authorized DoD DevSecOps platform]. It provides [function] to [users]."

## 3. System categorization (CNSSI 1253)

| Security objective | Impact level | Rationale |
|---|---|---|
| Confidentiality | (REPLACE Low/Moderate/High) | (REPLACE — information types & impact analysis) |
| Integrity | (REPLACE) | (REPLACE) |
| Availability | (REPLACE) | (REPLACE) |

- **Information types** (NIST SP 800-60 / mission-specific): (REPLACE)
- **Overlays applied** (CNSSI 1253 / DoD): (REPLACE — e.g., classified-information overlay, privacy overlay, intel overlay, space overlay, the DoD Cloud Computing SRG impact-level mapping for IL2/IL4/IL5)
- **DoD-specific assignment values** (from the RMF Knowledge Service): (REPLACE — reference)
- **Privacy:** (REPLACE — PII present? PTA/PIA status; SAOP coordination)

## 4. Authorization boundary

(REPLACE) Describe and diagram the boundary. Skeleton: "The authorization boundary comprises the
application container image(s), the source repository, the GitHub Actions CI/CD pipeline, the OCI
artifact registry (GHCR), and the application's runtime namespace on [the platform]. The underlying
cloud/infrastructure, the DevSecOps platform/software factory, the orchestrator, shared identity/
logging/secrets services, and the network perimeter are **inherited/common controls** provided by
[the RPOC / CSP] — see §8 (Customer Responsibility Matrix)."

See `docs/architecture.md` for the architecture & data-flow diagrams.

## 5. Operating environment & architecture

(REPLACE) Hosting environment (cloud/region/impact level); deployment topology (dev/test/staging/
prod tiers — RAISE expects multi-tier); the orchestrator (CNCF-conformant Kubernetes per the DoD
Reference Design); the base container image (recommend an Iron Bank image — see the container
crosswalk); key technologies; the security architecture (defense-in-depth, segmentation, "restricted"
Pod Security, default-deny networking, TLS everywhere, encryption at rest, least privilege). Represent
the architecture as code: `sample-app/Dockerfile`, `deploy/k8s/`, `deploy/terraform/`.

## 6. System interconnections & external dependencies

| Connected system / service | Type | Direction | Data exchanged | Agreement (ISA/MOU/SLA) |
|---|---|---|---|---|
| (REPLACE) | (REPLACE) | (REPLACE) | (REPLACE) | (REPLACE) |

External software dependencies: see the SBOM (`evidence/sbom/`) and `evidence/emass-package/hardware-software-list.csv`.

## 7. Ports, Protocols, and Services (PPSM)

| Port | Protocol | Service | Direction | Purpose | Boundary | Data classification | PPSM CAL category | Source/Dest | Justification |
|---|---|---|---|---|---|---|---|---|---|
| 443 | TCP/HTTPS (TLS 1.2+) | Application API | Inbound | HTTPS access to the API | Boundary | (REPLACE) | (REPLACE per the DoD PPSM CAL) | Authorized clients | Primary service interface |
| (REPLACE — add a row per port/protocol/service) | | | | | | | | | |

This table is the source for `evidence/emass-package/ppsm.csv`. Register all PPS in the DoD PPSM.

## 8. Control implementation & responsibility (the heart of the SSP)

- **Selected control baseline:** (REPLACE) NIST SP 800-53 Rev 5 — [Moderate/High] baseline per CNSSI 1253, plus the overlays in §3 and the DoD-specific assignment values. This repo's `compliance/control-catalog/control-catalog.yaml` contains a **curated subset** (the pipeline-evidenced + key process controls); **you must complete the full applicable baseline** with implementation statements / inheritance / NA determinations.
- **Common / inherited controls (Customer Responsibility Matrix):** see `compliance/templates/customer-responsibility-matrix.md`. The RPOC/CSP provides (typically): infrastructure & physical/environmental (PE-*), large parts of AC/IA (enterprise IdP, MFA, DoD PKI), AU (centralized logging/SIEM), SC (perimeter, encryption-at-rest infra, cross-domain), CP (backup/DR infra), IR (CSSP/SOC), MA, MP, PS (personnel), CM/SA at the platform layer, and the SR controls covered by using Iron Bank images. Mark these "Inherited"/"Manually Inherited" in eMASS or attach the CRM. The application is responsible for the controls in `control-catalog.yaml` plus the rest of the application-layer baseline.
- **Per-control implementation:** maintained in `control-catalog.yaml` and rendered to `evidence/boe/controls.json` / the dashboard / `evidence/emass-package/controls.csv` each pipeline run, including: implementation status, responsibility, inherited-from, CCIs, the implementation narrative, the assessing pipeline gate(s), the last automated test result + rationale, and the related-finding counts. **The SCA makes the final test-result determination and signs the SAR.**
- **Assessment procedures:** per NIST SP 800-53A Rev 5 — each control's assessment objective is decomposed into determination statements assessed via Examine / Interview / Test (the catalog's `assessment` block summarizes this; eMASS exposes the APs). The pipeline performs the **Test** method automatically for the controls it evidences; Examine/Interview are performed by the SCA.

> **For the AO/SCA:** the live picture is the **GitHub Pages dashboard** and `evidence/emass-package/`. This SSP file is the narrative wrapper; the control data is generated and kept current.

## 9. Continuous monitoring (ISCM) strategy

See `compliance/conmon/continuous-monitoring-strategy.md` (the **CA-7** artifact; also the basis
for cATO Pillar 1 and the RAISE ConMon expectation). Summary: the DevSecOps pipeline re-assesses all
automated controls on every push/PR, daily, and on demand; the dashboard and the ATO Status issue
provide near-real-time status; a dated trend is appended each run; the POA&M tracks remediation with
SLAs; runtime/infrastructure ConMon is inherited from the platform; for edge/disconnected nodes,
ConMon is met at the Staging tier with periodic sync.

## 10. Risk assessment & POA&M

- **Risk assessment (RA-3):** threat modeling at design time + the pipeline's continuous risk inputs (severity-rated findings rolled into a control-status posture each run); updated on significant change / threat-environment change. (REPLACE — reference the system risk assessment report.)
- **POA&M (CA-5):** auto-generated each run from open findings above the policy threshold, in the eMASS column layout (`evidence/emass-package/poam.csv`), with scheduled completion dates from the remediation SLAs (RAISE: raw High+ in production = 21 calendar days), plus human-managed items. Residual risk for RAISE-incorporated apps must not exceed Moderate; out-of-scope items require AO escalation.

## 11. Contingency planning, incident response, configuration management plans

- **Contingency Plan / ISCP (CP-2):** (REPLACE — reference; note backup/DR is largely inherited; the repo + GHCR + Releases + the optional immutable artifact bucket retain code/artifacts/evidence.)
- **Incident Response Plan (IR-8):** (REPLACE — reference; coordinated with the platform/RPOC CSSP/SOC; root-cause feeds the SDLC.)
- **Configuration Management Plan (CM-9):** (REPLACE — reference; implemented via Git + branch protection + CODEOWNERS + the PR change-control checklist + the pipeline gates + the version-controlled IaC; see CM-2/CM-3/CM-4/CM-5/CM-6.)

## 12. Roles & responsibilities

See `compliance/roles-and-responsibilities.md` (AO/AODR, SCA, ISSM, ISSO, ISSE, PM/SO, and — for
RAISE — the Technical Authority, RPOC Owner, RPOC ISSM, Application Owner).

## 13. References

See `compliance/references.md` (the annotated bibliography of all governing policy/frameworks, with
version caveats — confirm each against the controlling source for your program).

---

### SSP change record

| Date | Version | Change | By |
|---|---|---|---|
| (REPLACE) | 0.1 | Initial SSP from the DSOP template | (REPLACE) |
