# Security Assessment Plan (SAP) — TEMPLATE

> The plan the **SCA** approves before assessing (RMF Assess step; NIST SP 800-37 Rev 2; NIST SP
> 800-53A Rev 5). For **RAISE**, the SAP does not require SCA approval per the RIG, but it is still
> the basis for the quarterly-review assessment. The SCA produces the **Security Assessment Report
> (SAR)** from executing this plan.

---

**System:** (REPLACE name / acronym / eMASS ID)
**Categorization / baseline:** (REPLACE)
**Assessment type:** ☐ Initial ☐ Annual ☐ Quarterly (RAISE) ☐ Significant-change ☐ cATO process assessment
**Assessment period:** (REPLACE)
**Assessor (SCA / SCAR / team):** (REPLACE — independence statement)

## 1. Scope

- Controls assessed: (REPLACE — the applicable baseline; for a quarterly RAISE review, the deltas since the last review). The curated, pipeline-evidenced controls are in `compliance/control-catalog/control-catalog.yaml`; the live test results are in `evidence/boe/controls.json` / the dashboard.
- Boundary assessed: (REPLACE — the app + pipeline + registry + runtime namespace; inherited/common controls assessed by the provider — reference the CRM).
- Out of scope / inherited: (REPLACE — list; reference `compliance/templates/customer-responsibility-matrix.md`).

## 2. Methods & objects (per SP 800-53A)

| Method | How it's done here | Objects |
|---|---|---|
| **Test** | Performed automatically by the DevSecOps pipeline on every run + daily: SAST (CodeQL/Semgrep), SCA (Trivy/Grype/Dependency-Check), SBOM (Syft), secrets (Gitleaks/TruffleHog), IaC (Checkov/KICS/Trivy-config/kube-linter/Conftest), container scan (Trivy/Grype/Hadolint/Dockle), DAST (OWASP ZAP), STIG/SCAP (OpenSCAP), license policy, OpenSSF Scorecard, unit tests. The SCA reviews the results and may re-run / spot-check. | The repo, the workflows, the built image, the running app, the scan reports, the signatures/attestations. |
| **Examine** | The SCA reviews: the SSP, this SAP, the crosswalks (`compliance/crosswalks/`), the policy-as-code (`policy/`), the control catalog, the pipeline definitions, the consolidated evidence (`evidence/findings.json`, `evidence/boe/`), the ConMon history, the dashboard, the eMASS package, branch-protection/CODEOWNERS settings, the CRM. | Documents, configurations, mechanisms, activities. |
| **Interview** | The SCA interviews: the ISSO/ISSM, the DevSecOps team (developers/ISSE), the platform/RPOC team (for inherited controls), the PM/SO. | Personnel. |

## 3. Assessment procedures

For each control in scope, execute the AP from SP 800-53A Rev 5 (the eMASS AP text is authoritative
for your instance): assess each determination statement using the method(s) above; record the
result (**Compliant / Non-Compliant / Not Applicable / Not Reviewed**) and the evidence examined.
The catalog's `assessment.objective` summarizes each curated control's objective; the pipeline's
automated test result + rationale (`evidence/boe/test-results.csv`) is the starting point — the SCA
validates it. Reconcile against the authoritative CCI list (`ccis-and-assessment-procedures.md`).

## 4. Schedule, logistics, rules of engagement

- (REPLACE — dates; access to the repo / GitHub org / the platform; any active testing (e.g., a deeper DAST/pen test) and its rules of engagement, deconfliction with the CSSP, and authorization (IATT if needed); points of contact; how findings are communicated.)

## 5. Reporting / deliverables

- **Security Assessment Report (SAR)** — the SCA's findings, the assessed result for each control, the risk level of each weakness, and recommendations. May be signed with open action items. Feeds the AO's authorization decision and the POA&M.
- **POA&M updates** — weaknesses from the assessment merged into `evidence/boe/poam.csv` (or via the POA&M issue template) with scheduled completion dates.
- **For RAISE:** the SAR is signed before the AO quarterly-review meeting; the AO sets the next review date.

## Approval

| Role | Name | Signature / handle | Date |
|---|---|---|---|
| Security Control Assessor (approves the SAP) | (REPLACE) | | |
| ISSM (concurs) | (REPLACE) | | |
| AO/AODR (informed) | (REPLACE) | | |
