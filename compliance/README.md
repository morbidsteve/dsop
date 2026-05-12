# `compliance/` — the RMF / RAISE / cATO compliance content

This directory holds the human-authored compliance artifacts and the master control catalog the
pipeline reads. The pipeline (under `.github/workflows/` and `scripts/`) consumes these to produce
the live evidence (`evidence/`), the AO dashboard (`site/`), and the eMASS submission package.

| Path | What | Edit when adopting? |
|---|---|---|
| `references.md` | Annotated bibliography of every governing policy/framework (RMF, DoDI 8510.01, cATO memo + Implementation Guide + Evaluation Criteria, DoD DevSecOps Reference Design family, RAISE 2.0 RIG, NIST 800-37/-53/-53A/-218, EO 14028 / NTIA SBOM / SLSA, eMASS, STIGs/Iron Bank, …) — with version caveats and "where to confirm the current version" pointers. | Re-verify versions; add dated notes. |
| `control-catalog/control-catalog.yaml` | ★ **The master file.** A curated subset of NIST SP 800-53 Rev 5 controls (the pipeline-evidenced + key process controls) with implementation statements, responsibility/inheritance, CCIs, the assessing pipeline gate(s), assessment methods/objective, and RAISE-gate / SSDF tags. `scripts/map_controls.py` reads this to produce `controls.json`. | **Yes — heavily.** Replace the `metadata` placeholders; tailor every narrative; add the full applicable baseline + overlays + DoD-specific values. |
| `control-catalog/ccis-and-assessment-procedures.md` | How CCIs and SP 800-53A Assessment Procedures relate to the catalog and to eMASS test results; the reconciliation checklist. | Read; reconcile CCIs against the authoritative DoD list. |
| `ssp/system-security-plan.md` | The **PL-2** System Security Plan (template; partly self-maintaining — control data comes from the catalog/pipeline). | **Yes** — system description, boundary, categorization, interconnections, PPSM, the narrative wrapper. |
| `conmon/continuous-monitoring-strategy.md` | The **CA-7** ISCM strategy (also cATO Pillar 1 + RAISE ConMon + the App-Owner Vulnerability Management Plan). | Tailor frequencies, SLAs (mirror `policy/thresholds.yaml`), reporting cadence, edge-ops. |
| `roles-and-responsibilities.md` | AO/AODR, SCA, ISSM/ISSO/ISSE, PM/SO, and the RAISE roles (TA, RPOC Owner, RPOC ISSM, Application Owner); how decisions flow. | Map your org's titles; fill in names in the SSP. |
| `crosswalks/raise-2.0-crosswalk.md` | ★ RAISE 2.0 RIG → this repo: the **8 Security Gates**, the **24 RPOC requirements**, the **App-Owner artifacts**, the **quarterly-review (QREV) deliverables**, residual-risk/21-day rules, roles. | Confirm against the current RIG. |
| `crosswalks/cato-evaluation-crosswalk.md` | DoD cATO **3 (+1) pillars** + Implementation Guide + Evaluation Criteria → this repo — **and the gaps** (esp. active cyber defense). | Read carefully; don't over-claim cATO. |
| `crosswalks/ssdf-800-218-crosswalk.md` | NIST SSDF **PO/PS/PW/RV** → this repo; supports the CISA Secure Software Development Attestation Form + EO 14028 §4e. | Adapt examples. |
| `crosswalks/emass-crosswalk.md` | eMASS data areas (Controls / POA&M / Artifacts / HW-SW / PPSM / Workflow) → this repo; POA&M import column reference + import gotchas. | **Confirm the POA&M import template against your eMASS instance** before importing. |
| `crosswalks/devsecops-reference-design-crosswalk.md` | DoD Enterprise DevSecOps **10-phase lifecycle** + control gates + the software-factory layering + Iron Bank → this repo. | Cite which approved Reference Design your platform aligns to. |
| `templates/poam-template.csv` | The eMASS-style POA&M column layout the generator emits (with an example row). | Reference. |
| `templates/authorization-decision-document.md` | The **CA-6** ADD template (ATO / ATO-with-conditions / IATT / cATO / RAISE incorporation / DATO). | Fill in at authorization time. |
| `templates/security-assessment-plan.md` | The **SAP** template the SCA approves (basis for the SAR). | The SCA fills in. |
| `templates/customer-responsibility-matrix.md` | The CRM / control-inheritance template (what you inherit from the RPOC/CSP/platform/Iron Bank/enterprise). | **Yes** — reconcile against the providers' CRMs. |

## The golden rule

**Confirm everything against the controlling documents for your program.** This content is built
from the public versions; several authoritative sources are CAC-restricted and may be newer (the
RMF Knowledge Service, the eMASS User Guide & POA&M template, RAISE RIG annexes, DoD overlays). The
SCA, ISSM, and AO are the authorities — this repo feeds them; it does not replace them. Where this
content is uncertain, it says so (look for ⚠️ in `references.md` and the crosswalks).
