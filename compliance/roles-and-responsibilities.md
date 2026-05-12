# Roles & Responsibilities

The RMF / DevSecOps / RAISE roles touched by this repository, what they do, and where they
interact with it. (Authoritative definitions: NIST SP 800-37 Rev 2; DoDI 8510.01; DoDI 8500.01;
RAISE 2.0 RIG Table 1. Confirm titles/duties against your component's RMF Process Guide.)

> **Note on RAISE vs. classic RMF role names:** RAISE 2.0 v1.0 uses **CIO/SISO, AO, SCA, Technical
> Authority (TA), RPOC Owner, RPOC ISSM, Application Owner** — it does **not** separately define
> ISSO/ISSE. Classic RMF/DoD uses ISSM/ISSO/ISSE. Map between them per the table below; pick one
> taxonomy in your SSP and be consistent.

---

## RMF / DoD roles

| Role | Responsibilities | Touchpoints in this repo |
|---|---|---|
| **Authorizing Official (AO)** | Senior official who formally accepts risk and renders the authorization decision (ATO / ATO with conditions / IATT / DATO); for cATO, works with the Component CISO and **DoD CISO**; for RAISE, issues the platform/app authorization and **delegates assessment authority to the RPOC ISSM**; conducts ongoing/quarterly/annual reviews; approves pen-test requests, risk acceptances, and SLA exceptions. (DoDI 8510.01: AOs with "Very High" residual risk coordinate with the DoD CISO.) | The **GitHub Pages AO dashboard**; the auto-maintained **"ATO Status"** issue; `compliance/templates/authorization-decision-document.md`; the **control-deviation / risk-acceptance** issue template; `evidence/emass-package/`. |
| **AO Designated Representative (AODR)** | Formally appointed, qualified delegate acting for the AO on most RMF actions (not the final authorization decision). | Same as the AO. |
| **Security Control Assessor (SCA / SCAR)** | Conducts the independent assessment of control implementation; develops/approves the assessment plan; produces & signs the **Security Assessment Report (SAR)**; for RAISE, reviews the deltas since the last quarterly review and signs the SAR before the AO meeting. | `compliance/templates/security-assessment-plan.md`; `evidence/emass-package/controls.csv` + `test-results.csv` + `artifacts/`; the dashboard; `evidence/findings.json`. The pipeline performs the **Test** assessment method automatically; the SCA performs Examine/Interview and validates everything. |
| **Senior Information Security Officer (SISO)** / Component CISO | Owns the Component's RMF/cybersecurity program; for cATO, notifies/coordinates with the DoD CISO; for RAISE (DON), the **DON CISO** office issues the RAISE policy. | (org-level) |
| **Information System Security Manager (ISSM)** | Manages the system's cybersecurity program; supports RMF implementation; maintains/reports A&A status; appoints/directs the ISSO; reviews the BoE. (For RAISE: the **RPOC ISSM** is the platform's ISSM **and** the AO-delegated decision-maker for incorporated apps.) | The dashboard; the **ATO Status** issue; PR/Code Owner review (RAISE Gate 6); `evidence/boe/poam.csv` (esp. High+ items); the eMASS package. |
| **Information System Security Officer (ISSO)** | Day-to-day system security; develops/maintains/tracks the SSP and POA&Ms under AO/ISSM direction; supports continuous monitoring. (RAISE equivalent: app-side support to the RPOC ISSM, within the Application Owner team.) | `compliance/ssp/system-security-plan.md`; `compliance/control-catalog/control-catalog.yaml`; the POA&M issue template; the dashboard. |
| **Information System Security Engineer (ISSE) / Systems Security Engineer** | Integrates security into the systems-engineering process; security architecture/design; required for programs acquiring a system (DoDI 8510.01). (RAISE equivalent: security engineering within the Application-Owner DevSecOps team or the RPOC engineering team.) | `policy/` (policy-as-code, thresholds, Rego, Semgrep rules); `.github/workflows/` (the pipeline); `docs/architecture.md`; the secure-by-default code/IaC. |
| **Program Manager (PM) / System Owner (SO)** | Responsible for system development, security, and operation through the life cycle; appoints the ISSM; resources RMF; develops/owns the authorization package; oversees the POA&M. (RAISE: part of the **Application Owner**.) | Owns the repository and the relationship with the RPOC/AO; signs the SLA; resources remediation. |
| **Common Control Provider** | Provides and assesses controls inherited by multiple systems (here: the RPOC / CSP / platform). | The **Customer Responsibility Matrix** (`compliance/templates/customer-responsibility-matrix.md`); the `inherited`/`hybrid` controls in `control-catalog.yaml`. |
| **Risk Executive (function)** | Organization-wide risk perspective; provides risk tolerance / framing (the "risk governance process" in the cATO Implementation Guide). | Feeds the thresholds/SLAs in `policy/thresholds.yaml` (PM-9). |
| **User Representative / Mission Owner** | Represents operational needs and operational risk. | Requirements/backlog; accepts operational risk trade-offs. |

## RAISE-specific roles (RIG Table 1)

| Role | Responsibilities | Touchpoints |
|---|---|---|
| **Technical Authority (TA)** | Reviews/certifies the RPOC's **CI/CD pipeline tools** for "usability and functional capability" (per the **DevSecOps CI/CD Assessment Guidebook v1.0**); signs the certification document the AO uses to confer RPOC status. | The explicit tool list in `.github/workflows/` and `policy/` (made transparent for assessment). |
| **RPOC Owner** | Overall state of the RAISE Platform of Choice (platform owner + engineering teams). | (platform-side) |
| **RPOC ISSM** | Cybersecurity of the RPOC; supports AO/SCA quarterly/annual reviews; the **AO-delegated decision-maker** for apps incorporated via RAISE; decides app fit; defines deployment process(es); monitors the pipelines; reviews High+ mitigations (with the Qualified Validator/Independent Assessor); enforces signed-image-only admission; records who implements the pipeline in the SLA. | The dashboard; PR/Code Owner review (Gate 6); `evidence/boe/poam.csv`; `deploy/`; the eMASS package. |
| **Application Owner** | Responsible for the **entire SDLC** of the application (the DevSecOps team + the program office); produces & maintains the RAISE App-Owner artifacts (see `crosswalks/raise-2.0-crosswalk.md` §B); signs the SLA with the RPOC Owner. | **This whole repository.** |
| **Qualified Validator / Independent Assessor** (RAISE) | Independently reviews High+ vulnerability mitigations. | `evidence/boe/poam.csv` (High+ items); record dispositions in POA&M comments / the risk-acceptance issue. |

## How decisions flow (typical RAISE-incorporated app)

1. **Application Owner** develops/operates the app via this pipeline → continuous evidence + the dashboard + the eMASS package.
2. **ISSE/ISSO** keep `policy/`, `control-catalog.yaml`, and the SSP current; **PM/SO** resources remediation.
3. **RPOC ISSM** (delegated by the AO) reviews changes (Gate 6), monitors the pipeline, and reviews High+ mitigations with the **Qualified Validator**.
4. **SCA** reviews the eMASS package deltas at the **quarterly review** and signs the **SAR**.
5. **AO** runs the quarterly/annual review, accepts residual risk (≤ Moderate for RAISE), sets the next review date, and (for the platform) updates the **Authorization Decision Document**.
6. **DoD CISO** (cATO only) grants/maintains cATO based on the BoE presented by the AO + Component CISO.
7. Throughout: the **TA** (re)certifies the RPOC's CI/CD tools on change; **CSSP/SOC** runs active cyber defense (the cATO ACD pillar).
