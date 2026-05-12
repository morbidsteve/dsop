# Authorization Decision Document (ADD) — TEMPLATE

> The **CA-6** artifact: the AO's signed decision. Part of the RMF authorization package minimum
> (DoDI 8510.01 Table 6: SSP/security plan, SAR, all POA&Ms, **authorization decision document**).
> For **cATO**, this is supplemented by the DoD-CISO cATO approval; for **RAISE**, the AO updates
> the **RPOC's** ADD to confer RPOC status and (separately) records the application's incorporation.
> Use your component's required ADD format if one is mandated.

---

**System name / acronym:** (REPLACE)
**eMASS System ID / DITPR-DON ID / DADMS ID:** (REPLACE)
**Categorization (C-I-A, CNSSI 1253):** (REPLACE)
**Control baseline + overlays:** (REPLACE)
**Authorization boundary:** (REPLACE — see the SSP §4)

## Decision

The Authorizing Official, having reviewed the Body of Evidence (System Security Plan, Security
Assessment Report, Plan of Action & Milestones, risk assessment, and the continuous-monitoring
status — see the DSOP dashboard at `https://<org>.github.io/<repo>/` and the eMASS submission
package), renders the following decision:

- ☐ **Authorization to Operate (ATO)** — effective (REPLACE date) through (REPLACE date, ≤ 3 years) or until ongoing-authorization conditions are met.
- ☐ **ATO with conditions** — conditions and timeline below.
- ☐ **Interim Authorization to Test (IATT)** — scope and period below.
- ☐ **Continuous ATO (cATO)** — no expiration; maintained while the required real-time risk posture is sustained; conditions below. *(DoD-CISO approval reference: REPLACE.)*
- ☐ **RAISE 2.0 incorporation** — the application is incorporated into the RPOC's ATO ((REPLACE RPOC name + its eMASS ID)); assessment authority is delegated to the RPOC ISSM; next quarterly review: (REPLACE date).
- ☐ **Denial of Authorization to Operate (DATO).**

## Risk determination

- **Residual risk level (overall):** (REPLACE Very Low / Low / Moderate / High / Very High). *(For RAISE-incorporated apps, must not exceed **Moderate**; for "Very High," DoD-CISO coordination is required per DoDI 8510.01.)*
- **Key residual risks accepted:** (REPLACE — reference the POA&M items / risk-acceptance issues.)
- **Rationale:** (REPLACE — why the risk is acceptable given the mission, the compensating controls, and the continuous-monitoring program.)

## Conditions / terms

1. (REPLACE — e.g., remediate POA&M items #__ by __; maintain the daily pipeline ConMon; keep the dashboard current; no Critical/High findings past the SLA window; report any boundary change.)
2. (REPLACE — e.g., for cATO: maintain alignment to the approved DevSecOps Reference Design; sustain active cyber defense with the CSSP; report MTTP and the other continuous-authorization metrics quarterly.)
3. (REPLACE — for RAISE: comply with the RPOC SLA; provide the App-Owner artifacts; mitigation statements to the RPOC ISSM before each release; isolate/remove workloads with overdue High+ findings pending an AO exception.)

## Continuous monitoring & review

- **ConMon strategy:** `compliance/conmon/continuous-monitoring-strategy.md` (CA-7).
- **Next review:** (REPLACE — quarterly for RAISE; annual RPOC review; cATO is continuous + revocable).
- **Re-authorization trigger:** (REPLACE — expiration date for a classic ATO; or "ongoing authorization — no fixed expiration; re-evaluated on significant change or degraded posture").

## Signatures

| Role | Name | Signature / GitHub handle | Date |
|---|---|---|---|
| Authorizing Official (or AODR) | (REPLACE) | | |
| Security Control Assessor (SAR signed) | (REPLACE) | | (SAR date) |
| ISSM | (REPLACE) | | |
| (RAISE) RPOC ISSM | (REPLACE) | | |
| (cATO) Component CISO / DoD CISO ref | (REPLACE) | | |
