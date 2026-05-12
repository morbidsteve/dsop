# CCIs and Assessment Procedures — how they relate to this repo

## Control Correlation Identifiers (CCIs)

A **CCI** decomposes a NIST SP 800-53 control statement into discrete, measurable, "atomic"
statements that can be assessed and tracked individually. DoD uses CCIs to tie controls to STIG
requirements and to eMASS test results. The `ccis:` list on each control in
`control-catalog.yaml` is **illustrative** — you must use the **authoritative DoD CCI list** for
your selected baseline (it ships with the DISA STIG/SCAP tooling and is reflected in eMASS).

- Where to get the authoritative list: the **DoD Cyber Exchange** (`public.cyber.mil`) ships the
  CCI List (`U_CCI_List.xml`); eMASS maps controls↔CCIs↔APs for you.
- Some Rev-5-only controls (notably parts of the **SR** family) had CCIs added later — the catalog
  marks a few as `CCI-Pending`; replace with the real CCIs from the current list.
- When you import test results to eMASS, results are recorded against **Assessment Procedures (APs)
  / CCIs**, not just the control acronym — so make sure the CCI mapping is correct.

## Assessment Procedures (APs) — NIST SP 800-53A Rev 5

Each control has one or more **Assessment Procedures**. An AP states an **assessment objective**
(decomposed into **determination statements**, which in Rev 5A may include organization-defined
parameters), to be assessed using one or more **assessment methods**:

- **Examine** — review documents, mechanisms, or activities (e.g., read the SSP control narrative, inspect the pipeline config, review scan reports).
- **Interview** — talk to personnel (e.g., the ISSO, developers, the platform team).
- **Test** — exercise the control and observe behavior (e.g., run the scanner, attempt a disallowed action, verify the image signature).

In this repo:
- The `assessment.methods` and `assessment.objective` fields in `control-catalog.yaml` summarize the AP for each curated control (the SCA uses the full SP 800-53A AP text / the eMASS AP).
- The **pipeline performs the `Test` method automatically** for the controls it evidences (running SAST/SCA/SBOM/secrets/IaC/container/DAST/STIG/license/supply-chain and verifying outcomes), and produces an automated **test result** (`Compliant` / `Non-Compliant` / `Not Reviewed` / `Not Applicable`) with a rationale and a link to the assessing run — see `scripts/map_controls.py` and `evidence/boe/controls.json` / `test-results.csv`.
- **`Examine` and `Interview` are performed by the SCA** (and by the ISSM/ISSO for self-assessment) — the repo provides the artifacts to examine (the SSP, the crosswalks, the policy-as-code, the scan reports, the ConMon history, the eMASS package) and the people to interview.
- The automated test result is a **first pass / continuous indicator** — the **SCA makes the final determination and signs the SAR**. Where the pipeline can't assess a control (process/manual controls with no `evidence` gates), the result is `Not Reviewed (Manual Assessment)` unless a `manual_assessment.result` is recorded.

## "Assess Only" controls

Some controls (e.g., certain organization-level or inheritable controls) are designated **"Assess
Only"** in DoD — they're assessed but not part of the system's authorization-decision risk
calculation, or they're inherited and assessed by the provider. Mark these appropriately in eMASS
and reference the provider's assessment / the CRM. The RMF Knowledge Service has the current
Assess-Only guidance (CAC).

## Reconciliation checklist when adopting this template

1. Replace the curated `ccis:` lists with the authoritative DoD CCI list for your baseline.
2. Add the full applicable control baseline (this file is a curated subset) with implementation statements, inheritance, and NA determinations.
3. Confirm the `assessment.methods`/`objective` against the SP 800-53A APs (the eMASS AP text is authoritative for your instance).
4. Identify all inherited/common controls (the platform/RPOC/CSP) and complete the Customer Responsibility Matrix.
5. Apply your CNSSI 1253 categorization, overlays, and DoD-specific assignment values (from the RMF Knowledge Service).
