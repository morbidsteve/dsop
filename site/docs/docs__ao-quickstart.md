# For the Authorizing Official / SCA / ISSM — how to read the evidence

You have three views into the same Body of Evidence; pick whichever is convenient.

## 1. The dashboard (the "intuitive interface")

**URL:** `https://<org>.github.io/<repo>/` (published automatically by the pipeline on every run).

Tabs:
- **Status** — authorization posture, the headline numbers (controls Compliant / Non-Compliant / Not Reviewed / Not Applicable; open POA&M items; overdue; findings by severity; OpenSSF Scorecard), the assessing commit/run, and the RAISE Security Gate status (which of the 8 ran this run).
- **Controls** — every applicable NIST 800-53 control: implementation status, responsibility (system/common/hybrid/inherited), the last automated **test result** + rationale, the implementation narrative, the assessing pipeline gate(s) and the linked evidence artifact(s), the related-finding counts, and the assessing run. Filter/search by family, status, result, RAISE gate. **The test result is an automated first pass — the SCA makes the final determination and signs the SAR.**
- **Findings** — every open finding across all scanners, normalized and deduplicated: tool, gate, severity, title, location/component, CVE/CWE, fix availability. Filter by tool / severity / gate. Click through to the GitHub code scanning alert or the run.
- **POA&M** — open items above the policy threshold, in the eMASS column layout: control, source, raw/adjusted severity (CAT), scheduled completion date, milestones, residual risk, **overdue** and **out-of-RAISE-scope** flags. This is what gets exported to eMASS.
- **ConMon** — the continuous-monitoring trend over time (findings by severity, control results, POA&M open/overdue, SBOM component count) — your CA-7 / cATO-Pillar-1 view.
- **Pipeline** — the DevSecOps lifecycle, every gate, the tool that runs it, the controls it evidences, and the pass/fail policy — with the RAISE 2.0 Security Gate crosswalk.
- **Package** — download the latest eMASS submission package and read its manifest/summary.

## 2. The "ATO Status" issue (GitHub-native, always current)

A single pinned issue labeled `ato-status`, auto-updated on every pipeline run (and weekly) by the
`ato-status-report` workflow. It has the same headline numbers, a link to the dashboard and the
assessing run, the overdue POA&M items, the RAISE gate status, and the recent ConMon trend table.
Watch the repo to get notified on changes; comment to record decisions.

## 3. The eMASS submission package (the formal deliverable)

Attached to every version-tag GitHub Release as `emass-package.zip` (and produced as the
`body-of-evidence` / `emass-package` workflow artifact on every run). Contents:
- `ato-package-summary.md` — human-readable index + posture snapshot + submission steps.
- `MANIFEST.json` — machine index: every file → the control(s)/CCI(s) it supports → the eMASS artifact category/type.
- `controls.csv` / `controls.json` — per-control implementation status, responsibility, CCIs, narrative.
- `test-results.csv` — control test results + rationale + the assessing run.
- `poam.csv` — the POA&M in the eMASS column layout.
- `hardware-software-list.csv` — the software baseline from the SBOM (HW rows = template).
- `ppsm.csv` — the Ports/Protocols/Services template.
- `system-security-plan.md` — the SSP.
- `artifacts/<gate>/...` — the raw scan reports, SBOMs, and attestations.

See `docs/emass-submission-runbook.md` for what to do with it.

## What "good" looks like at decision time

- Controls: a high automated-assessment coverage %, no Non-Compliant controls at the High/Critical level without an accepted-risk record, manual/process controls assessed by the SCA.
- Findings: no open Critical/High that aren't in the POA&M with a remediation date; nothing overdue; nothing out-of-RAISE-scope (residual risk ≤ Moderate) without an AO escalation.
- ConMon: the pipeline is green and running daily; the trend is flat-or-improving; mean-time-to-patch is within the SLA.
- Supply chain: SBOMs present (SPDX + CycloneDX), the image is signed, SLSA provenance is attached, OpenSSF Scorecard is reasonable.
- Documentation: the SSP, the SAR (SCA-signed), the POA&M, and the authorization decision document are complete; the CRM reconciles with the providers; the references are version-verified.

## Things to ask about (the gaps this repo can't close on its own)

- **Active cyber defense** (cATO Pillar 2): the CSSP/SOC relationship, runtime IDS/IPS/EDR, threat-intel ingestion, incident-response exercises, JFHQ-DODIN/USCYBERCOM coordination — this repo provides the *vulnerability-management* half, not ACD.
- **Inherited/common controls:** the provider CRMs (CSP, the DevSecOps platform / RPOC, the Iron Bank base image, enterprise services) — are they current and authorized?
- **Categorization & overlays:** done per CNSSI 1253 with the right overlays and DoD-specific values?
- **Approved DevSecOps Reference Design:** which one does the platform align to (cATO Pillar 3)?
- **STIG/SCAP content:** has the program supplied its actual DISA STIG/SRG SCAP content to the `stig` gate (the repo ships a placeholder), and are open STIG findings in the POA&M?
- **eMASS POA&M template:** has the POA&M CSV been reconciled against your eMASS instance's import template?

## Decisions you can record right here

Use the issue templates: **POA&M item** (track/accept a weakness), **Control deviation / risk
acceptance** (the AO/AODR decision block is built in), **ATO/cATO/RAISE milestone** (track the
authorization workflow). And the `compliance/templates/authorization-decision-document.md` for the
formal ADD.
