# eMASS submission runbook

How to take the pipeline-generated package into eMASS. The pipeline does **not** call eMASS (this
is an IL2 scaffold — no eMASS credentials in the repo); a person with the appropriate eMASS role
uploads it.

> ⚠️ **Confirm the exact eMASS screens and the POA&M import template against your eMASS instance's
> CAC-protected User Guide before you start** — labels, value lists, and the POA&M column
> headers/order can vary by deployment and version. See `compliance/crosswalks/emass-crosswalk.md`.

## 0. Get the package

- Tag a release (`vX.Y.Z`) → the `emass-package-release.yml` workflow builds the package and
  attaches **`emass-package.zip`** (+ `ato-package-summary.md`, `poam.csv`, `controls.csv`) to the
  GitHub Release. (Or download the `body-of-evidence` / `emass-package` workflow artifact from any
  pipeline run.)
- Unzip it. Read `ato-package-summary.md` (human index + posture snapshot) and `MANIFEST.json`
  (machine index: every file → control(s)/CCI(s) → eMASS artifact category/type).

Package contents recap:
```
emass-package/
  MANIFEST.json
  ato-package-summary.md
  system-security-plan.md
  controls.json / controls.csv
  test-results.csv
  poam.csv
  hardware-software-list.csv
  ppsm.csv
  artifacts/<gate>/...        (SAST/SCA/SBOM/secrets/IaC/container/DAST/STIG/license/scorecard reports + attestations + the normalized findings.json)
emass-package.zip
```

## 1. Verify / update the System record

- In eMASS, open (or register) the system. Reconcile **System Details** against `MANIFEST.json > system`:
  name, acronym, categorization (C-I-A), control baseline + overlays, eMASS System ID, DITPR-DON ID,
  DADMS ID, authorization boundary summary, and (for RAISE) the RPOC the app is incorporated into.
- Confirm the selected control set / overlays in eMASS matches your SSP §3 and `control-catalog.yaml`.

## 2. Update Security Controls (implementation)

- For each control, set the **implementation status** (Implemented / Planned / Inherited / Manually
  Inherited / Not Applicable / Hybrid), the **responsibility**, and the **implementation narrative**
  from `controls.csv` (the `controls.json` has the same data structured). For **Inherited** controls,
  mark them inherited and link the provider package, or attach `customer-responsibility-matrix.md`.
- Remember `control-catalog.yaml` is a **curated subset** — you still owe eMASS the full applicable
  baseline. Complete the rest from your SSP.

## 3. Enter Test Results + attach Artifacts

- For each control, enter the **test result** (Compliant / Non-Compliant / Not Applicable / Not
  Reviewed) and rationale from `test-results.csv`. (These are the pipeline's automated first pass —
  the **SCA** validates and finalizes them.) Test results are recorded against the control's
  **Assessment Procedures / CCIs**.
- Upload the files in `artifacts/<gate>/...` to the eMASS **Artifacts Library**. Use `MANIFEST.json
  > artifacts` to set each file's **category** and **type** and to associate it with the right
  control(s)/CCI(s). At minimum upload: the SAST report(s), the SCA/dependency report, the SBOM(s)
  (SPDX + CycloneDX), the container scan + hardening report, the IaC scan report, the DAST report,
  the STIG/SCAP results (+ `.ckl`), the license report, the OpenSSF Scorecard report, the
  consolidated `findings.json`, and the `conmon_history.json`. Also upload the SSP, the SAR (once
  the SCA signs it), and the authorization decision document.

## 4. Import the POA&M

- **Before importing:** open your eMASS instance's POA&M Excel/CSV import template. Compare its
  column headers and order against `poam.csv` (see the column reference in
  `compliance/crosswalks/emass-crosswalk.md`). eMASS may require a specific order and may have
  additional columns (e.g., a workflow-status or external-UID column). Adjust `poam.csv` (or re-run
  `scripts/generate_poam.py` with `--office`/`--poc` set, then post-edit) to match the template.
- Import. Then in eMASS: link each POA&M item to its control(s)/CCI(s)/test result; verify the
  **Scheduled Completion Date**, **milestones**, **POC**, **resources**, **status**, **severity**,
  and **residual risk**. For items flagged `Overdue` or `Out of RAISE scope` in the CSV's Comments,
  attach the AO exception / risk-acceptance record.

## 5. Update the Hardware/Software baseline and PPSM

- Import the **Software** rows from `hardware-software-list.csv` (derived from the SBOM). Add the
  **Hardware** rows from your SSP / the hosting platform inventory (usually inherited from the
  RPOC/CSP — the CSV has a template note).
- Update **PPSM** from `ppsm.csv` (a template — populate it from your SSP §7); ensure everything is
  also registered in the DoD PPSM with the correct CAL category assurance level.

## 6. Route the package (workflow)

- Submit the controls into the **Control Approval Chain (CAC)** for SCA review; once the SCA
  completes the assessment and signs the **SAR**, initiate the **Package Approval Chain (PAC)** for
  the AO decision.
- For **RAISE**: this package is your quarterly-review packet — give the link to the **RPOC ISSM**;
  the SCA reviews the deltas and signs the SAR before the AO meeting; the AO accepts residual risk
  (≤ Moderate), records the incorporation, and sets the next review date.
- For **cATO**: the AO + Component CISO present the BoE to the **DoD CISO** for the cATO decision
  (cATO has no expiration but is revocable). Track via the ATO milestone issue.
- Record the AO's decision in `compliance/templates/authorization-decision-document.md` and as a
  comment on the relevant ATO milestone issue.

## 7. Keep it current (continuous)

- Every pipeline run regenerates the evidence. On a meaningful change (new release, new findings,
  closed POA&M items, control changes), re-export and update eMASS — or, if your program provisions
  the **eMASS REST API** (DoD PKI client cert + `api-key`), a future workflow can push
  `controls.json` / `test-results.csv` / `poam.json` / artifacts directly (out of scope for this
  IL2 scaffold; if you add it, treat the cert/key as the org's most sensitive secrets, restrict the
  environment, and require a human approval gate).
- The ConMon trend (`conmon_history.json`) + the dashboard + the ATO Status issue are your
  between-export status views.

## Quick checklist

- [ ] System record reconciled with `MANIFEST.json > system`
- [ ] Control implementation status + narrative + responsibility updated (full baseline, not just the curated subset)
- [ ] Inherited controls marked / CRM attached
- [ ] Test results entered; rationale recorded; SCA validating
- [ ] Artifacts uploaded with correct category/type and control/CCI associations (per `MANIFEST.json`)
- [ ] POA&M template reconciled, imported, items linked, dates/milestones/POC/severity/residual-risk verified, exceptions attached
- [ ] HW/SW baseline + PPSM updated
- [ ] SSP, SAR (SCA-signed), and authorization decision document uploaded
- [ ] Package routed through CAC → PAC (and to the DoD CISO for cATO; to the RPOC ISSM for RAISE)
- [ ] AO decision recorded (ADD + ATO milestone issue)
