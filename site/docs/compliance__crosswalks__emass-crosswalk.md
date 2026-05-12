# eMASS ↔ this repository — crosswalk + import notes

How the pipeline's outputs map onto the **Enterprise Mission Assurance Support Service (eMASS)**
data areas, and what to watch for when importing.

> ⚠️ **The exact eMASS screens, value lists, and the POA&M import-template columns (names, order,
> required flags) are defined in the CAC-protected eMASS User Guide for your eMASS instance** (and
> vary slightly by deployment — RMF eMASS vs. NISP eMASS vs. the CMMC eMASS instance, and by
> version). Treat the column names below as the well-documented field set, not as gospel — open
> your instance's POA&M import template and reconcile before importing. The eMASS **REST API** (if
> your program has provisioned it: client cert + `api-key`) consumes the same data; this repo does
> not call the API (IL2 scaffold) but the package shapes match what the API expects.

---

## eMASS data area → repo artifact

| eMASS area | What goes there | From this repo |
|---|---|---|
| **System Details / Overview** (name, acronym, type, org, categorization C-I-A, overlays, authorization status/dates, system description, registration type, DITPR-DON/DADMS IDs) | System facts | `compliance/control-catalog/control-catalog.yaml > metadata` (and `compliance/ssp/system-security-plan.md`); surfaced in `evidence/emass-package/MANIFEST.json > system`. Reconcile the eMASS record against this. |
| **Security Controls** (per control/CCI: implementation status — Implemented / Planned / Inherited / Manually Inherited / Not Applicable / Hybrid; implementation guidance/narrative; responsibility/inheritance; estimated/actual completion dates; **test results** — Compliant / Non-Compliant / Not Applicable / Not Reviewed — tied to **Assessment Procedures (APs)** and **CCIs**) | Implementation statements + test results | `evidence/emass-package/controls.csv` / `controls.json` (status, narrative, responsibility, CCIs, RAISE/SSDF tags) and `test-results.csv` (test result + rationale + assessing run). The catalog's `assessment.methods`/`assessment.objective` map to the SP 800-53A APs. **Inherited** controls: mark inherited in eMASS (or attach the Customer Responsibility Matrix) — see `compliance/templates/customer-responsibility-matrix.md`. |
| **POA&M** (per item: status; scheduled completion date; milestones with dates & change history; point of contact; resources required; comments; severity/risk; source; linkage to control(s)/CCI(s)/test results) | The POA&M | `evidence/emass-package/poam.csv` (eMASS column layout — see below) / `boe/poam.json`. Generated each run from open findings above threshold, plus human-managed items via the POA&M issue template. |
| **Artifacts / Artifacts Library** (uploaded evidence files, each tagged with a **category** and **type**, expiration date, associations to controls/POA&Ms) | The scan reports, SBOMs, attestations, SSP, etc. | `evidence/emass-package/artifacts/<gate>/...` plus `MANIFEST.json > artifacts`, which gives each file an `emass_artifact_category`, `emass_artifact_type`, and the list of `supports_controls` / `supports_ccis` to associate it to. (Category/type hints in `scripts/build_emass_package.py` — adjust to your instance's value lists.) |
| **Hardware/Software baseline** (Hardware List / Software List — approved/installed software) | The SW baseline | `evidence/emass-package/hardware-software-list.csv` (SW rows derived from the merged SBOM `sbom/components.json`; HW rows are a template — populate from the SSP / hosting-platform inventory, usually inherited). |
| **PPSM — Ports, Protocols, and Services Management** (registered ports/protocols/services, consistent with the DoD PPSM CAL) | The PPSM registration | `evidence/emass-package/ppsm.csv` (template — populate from the SSP's PPSM section; one row per port/protocol/service). |
| **STIG / vulnerability scan import** (asset/SCAP results, `.ckl` checklists, ACAS/Nessus, container scans) | STIG/SCAP & scanner results | `evidence/stig/**` (OpenSCAP XCCDF results + a `.ckl` skeleton — supply your DISA STIG/SRG SCAP content), `evidence/container/**`, `evidence/sca/**` (Trivy/Grype/Dependency-Check). Open STIG findings → POA&M items. |
| **Authorization / Workflow** (the Control Approval Chain (CAC) and Package Approval Chain (PAC); RMF step tracking; authorization decision documents; eMASS-generated reports) | The authorization workflow | `compliance/templates/authorization-decision-document.md` (the ADD); the package itself (`emass-package/`) is what you route through the CAC/PAC; the ATO milestone issue template tracks the workflow milestones. |
| **Dashboards / Reports** (controls scorecard, POA&M, system status & ATO, FISMA/CIO metrics) | Status/reporting | The repo publishes its own GitHub Pages dashboard + the auto-maintained ATO Status issue + `controls_summary.json` / `conmon_history.json` — use these alongside eMASS's built-in dashboards (and they feed the RPOC's near-real-time view per RAISE). |

---

## POA&M import — column reference

`evidence/emass-package/poam.csv` (and `evidence/boe/poam.csv`) is emitted with these columns
(also see `compliance/templates/poam-template.csv`). The first ~21 mirror the well-documented
eMASS POA&M field set; the last 5 are repo bookkeeping (ignored on import):

1. **Control Vulnerability Description** — the weakness (finding title + description).
2. **Security Control Number (NC/NA controls)** — the associated NIST 800-53 control acronym (e.g., `RA-5`).
3. **Office/Org** — responsible office (set via `--office`, defaults to a placeholder — edit).
4. **Security Checks (CCIs)** — associated CCI(s) from the control catalog.
5. **Resources Required** — effort/resources to remediate.
6. **Scheduled Completion Date** — `first_seen + sla_days[severity]` (RAISE: High+ in prod = 21 calendar days).
7. **Milestone with Completion Date** — milestones, each with a target date.
8. **Milestone Changes** — change history (blank initially).
9. **Source Identifying Control Vulnerability** — which scan/assessment found it (e.g., "Pipeline SCA — Trivy (rule CVE-…)").
10. **Status** — Ongoing / Risk Accepted / Completed / Not Applicable.
11. **Comments** — overdue/out-of-RAISE-scope flags, CVE list, fix availability, etc.
12. **Raw Severity Value** — `CAT I/II/III (Critical/High/Medium/Low)`.
13. **Mitigations** — compensating controls / why not yet remediated (complete per the SCA Risk Assessment Guide).
14. **Severity Value** — adjusted severity (`CAT I/II/III`) — adjust after mitigations.
15. **Relevance of Threat** — High / Moderate / Low.
16. **Likelihood** — High / Moderate / Low.
17. **Impact** — Very High / High / Moderate / Low.
18. **Impact Description** — impact to C-I-A (complete per categorization).
19. **Residual Risk Level** — Very High / High / Moderate / Low / Very Low (must not exceed Moderate for RAISE-incorporated apps).
20. **Recommendations** — recommended remediation.
21. **Point of Contact** — name / org / email (set via `--poc`, defaults to a placeholder — edit).
22–26 (repo bookkeeping): **Finding Fingerprint**, **Tool**, **First Seen**, **Age (days)**, **Overdue**.

**Before importing:** (a) open your eMASS instance's POA&M import template and check that the
column **headers and order** match — eMASS may require a specific order and may have additional
columns (e.g., a workflow-status or external-UID column); (b) decide how `Office/Org` and `Point of
Contact` should be populated and re-run `generate_poam.py` with `--office`/`--poc`, or post-edit
the CSV; (c) confirm the **Status** vocabulary matches your instance; (d) for items flagged
"out-of-RAISE-scope" or "overdue", attach the AO exception / risk-acceptance record.

---

## Quick mapping for the eMASS REST API (if used later)

The repo doesn't call the API, but if your program provisions it (DoD PKI client cert + `api-key`):

| API capability | Feed it from |
|---|---|
| `PUT` control implementation details | `controls.json` (implementation status, narrative, responsibility, completion dates) |
| `POST` control test results | `test-results.csv` (compliance status, tested-by, date, AP/CCI, comments) |
| `POST/PUT` POA&M items + `POST/PUT` milestones | `boe/poam.json` (the structured form has the milestone list, POC fields, dates, etc.) |
| `POST` artifacts (+ `PUT` metadata: category/type/associations) | `emass-package/artifacts/**` + `MANIFEST.json > artifacts` (category/type/supports_controls/supports_ccis) |
| `POST/PUT` hardware & software baseline | `emass-package/hardware-software-list.csv` |
| `POST` static-code / container / device scan results | `evidence/sast/**`, `evidence/container/**`, `evidence/stig/**` (transform to the API's expected schema) |
| `POST` to the CAC / initiate a PAC | After the SCA review — route the package |

A future workflow could automate this (cert + `api-key` in GitHub Actions secrets); it's
intentionally out of scope for this IL2 scaffold so no eMASS credentials live in the repo. If you
add it, treat the cert/key as the most sensitive secrets in the org, restrict the environment, and
require a human approval gate.
