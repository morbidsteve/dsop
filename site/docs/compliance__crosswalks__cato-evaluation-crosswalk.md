# DoD continuous ATO (cATO) ↔ this repository — crosswalk

Maps the DoD CIO **"Continuous Authorization To Operate (cATO)" memo (~3 Feb 2022)**, the
**"DevSecOps Continuous Authorization Implementation Guide" v1.0 (Mar 2024)**, and the
**"DevSecOps Continuous Authority to Operate — Evaluation Criteria" (cleared Dec 2023)** to what
this pipeline provides — **and, importantly, what it does NOT** (so you don't over-claim).

> ⚠️ cATO is granted at the **DoD CISO** level. A system must **already have an ATO** and be in the
> RMF **Monitor** step. cATO **has no expiration** but is **revocable**. The authoritative
> Evaluation Criteria detail (Appendix B "requirements targets and objectives") lives on the RMF
> Knowledge Service (CAC). The Implementation Guide is **Distribution Statement C** (US Gov +
> contractors), not unrestricted public. Confirm everything below against the controlling versions.

---

## The three (+1) cATO competencies/pillars

| Pillar | cATO requirement | This repo | Gap / who else must provide |
|---|---|---|---|
| **1. Continuous Monitoring of RMF controls** | Near-real-time visibility of all RMF controls inside the boundary; a **system-level dashboard** the AO uses to make real-time risk decisions across the AOR; automated, near-real-time monitoring/assessment of *all* controls (incl. common controls). | ✅ The pipeline re-assesses all automated controls on every push/PR, daily, and on demand; `map_controls.py` produces a per-control status roll-up; `update_conmon.py` keeps a dated trend (findings by severity, control results, POA&M size/overdue, mean-time-to-patch inputs, SBOM count); the **GitHub Pages dashboard** + the **ATO Status issue** are the system-level views; `policy/thresholds.yaml` encodes risk thresholds & SLAs. (CA-7.) | ⚠️ **Common/inherited controls** (host/cloud vulnerability scanning, infrastructure ConMon, log analytics) are monitored by the **platform/RPOC/CSP** — this repo covers the application + pipeline portion. ⚠️ "Across the AOR" / multi-system roll-up is the AO's responsibility (aggregate multiple repos' dashboards). |
| **2. Active Cyber Defense (ACD)** | Real-time threat response — **not just "scans and patching"**: constant comms with **CSSPs / Component cyber forces / JFHQ-DODIN / USCYBERCOM**, ingesting cyber threat intel, deploying countermeasures in real/near-real time, sharing indicators. | ⚠️ **Largely out of scope for this repo.** The pipeline contributes the *vulnerability-management* half (continuous scanning, fast remediation SLAs, the SI-2/SI-3/SI-4 evidence, the build-system monitoring via OpenSSF Scorecard) and feeds telemetry to the SIEM — but **ACD is an operations-organization capability**: your **SOC/CSSP**, runtime IDS/IPS/EDR, threat-intel ingestion, incident response, and the relationships with JFHQ-DODIN/USCYBERCOM. Document those in the SSP (SI-4, AU-6, IR-4/IR-6) and reference the CSSP agreements. | ❌ Provide ACD evidence from your CSSP/SOC: threat-feed ingestion, real-time countermeasure deployment, incident-response exercises, indicator sharing, JFHQ-DODIN coordination. |
| **3. Adopt an approved DoD Enterprise DevSecOps Reference Design** (a **Software Factory** with guardrails/control gates) **+ a Secure Software Supply Chain** (incl. **SBOM**) | The system embraces the DoD Enterprise DevSecOps Strategy and aligns to an **approved Reference Design**; ≥ dev/test/staging environments on a modern cloud; ≥ 1 pipeline with automated **guardrails and control gates collecting continuous evidence**; built-in **dashboards & automated alerts** with a feedback mechanism; the DSOP delivered/operated as its own system; input from a **risk governance process** (acceptable residual-risk tolerances); adherence to the DevSecOps Fundamentals (Activities & Tools); a Secure Software Supply Chain producing SBOM/provenance. | ✅ This pipeline IS the guardrails + control gates collecting continuous evidence (SAST/SCA/SBOM/secrets/IaC/container/DAST/STIG/license/supply-chain + build-test), with dashboards/alerts (Pages dashboard + ATO Status issue + GitHub code scanning alerts + Dependabot) and a feedback loop (findings → POA&M → PRs → re-assessment). Secure Software Supply Chain: SPDX + CycloneDX SBOMs, SLSA build provenance, cosign signing, pinned dependencies, approved sources, OpenSSF Scorecard. See `devsecops-reference-design-crosswalk.md` and `ssdf-800-218-crosswalk.md`. | ⚠️ You must run on (or be) an **approved Reference Design** platform (DSOP/software factory) with the dev/test/staging environments and the cloud — this repo is the *pipeline & evidence*, not the platform. ⚠️ The **risk governance process** (org-level acceptable-residual-risk tolerances) is PM-9 — provide it; `policy/thresholds.yaml` should reflect it. |

---

## cATO Implementation Guide — software-factory expectations → this repo

| Expectation (Mar 2024 Implementation Guide) | This repo |
|---|---|
| Software factory = DSOP + people + process + cloud hosting; ≥ dev, test, staging (optionally prod) | This repo is the **pipeline & evidence engine** that runs on/feeds the software factory; the multi-tier environments + cloud are the platform's. `deploy/` shows the deploy artifacts; `policy/thresholds.yaml` and the ConMon strategy assume multi-tier. |
| ≥ 1 DevSecOps pipeline with automated **guardrails and control gates** collecting evidence for **continuous risk determinations** | `.github/workflows/devsecops-pipeline.yml` — all gates run on every change + daily; `policy/thresholds.yaml` defines pass/fail; `scripts/` turn the evidence into continuous control-status + POA&M + ConMon-trend determinations |
| Built-in **dashboards and automated alerts** with an active feedback mechanism | GitHub Pages dashboard + ATO Status issue + GitHub code scanning + Dependabot alerts + the dependabot-auto triage; feedback loop = finding → POA&M → PR → re-assessment |
| DSOP delivered/operated as its **own system** (a service to app teams) | (platform-side) — if you're building the DSOP, treat it as its own RMF system; this repo is then a *reference for app teams onboarding to it* |
| Input from a **risk governance process** providing common acceptable residual-risk tolerances | `policy/thresholds.yaml` is where those tolerances are encoded for the app; the org-level process is PM-9 |
| Adherence to the **DevSecOps Fundamentals (Activities & Tools)** | `devsecops-reference-design-crosswalk.md` maps the lifecycle phases & activities to the gates; `policy/` documents the tool selections |
| **Continuous-authorization metrics** — e.g., **Mean Time to Patch**; guardrail/control-gate trend metrics; feedback-frequency metrics; mitigation-effectiveness; security-posture-by-stage; container age vs. redeploy frequency; % test coverage / functional tests | `update_conmon.py` records the inputs (findings by severity over time, POA&M open/overdue, control results trend, mean-time-to-patch derivable from finding first-seen vs. close, SBOM component count); coverage from the build gate; the dashboard's ConMon view visualizes the trend. Extend `update_conmon.py` to compute any additional metrics your AO wants. |
| **Two use cases:** UC1 — inside the DSOP boundary (factory has an ATO, deploys into its own prod; cATO issued to the factory); UC2 — outside the DSOP boundary (deploys into a separate env with its own ATO; needs cross-boundary agreements/reciprocity) | If your app deploys onto an authorized platform's prod inside that platform's boundary → UC1 territory (the platform's cATO; your app is incorporated — RAISE 2.0 is the Navy mechanism for that). If your app/build artifacts deploy onto a *separate* authorized environment (e.g., a weapon system, Navy ships) → UC2 (cross-boundary agreements + reciprocity — see the DoD Cybersecurity Reciprocity Playbook). The `emass-package/` output supports either. |
| Assessment method: AO approves an assessment team; assess the **DSOP + the process + the people/teams** against weighted criteria; a periodic process assessment replaces point-in-time control compliance checks; reference NIST SP 800-161r1 for supply-chain | This repo makes the *process* and the *evidence* transparent and continuous (the gates, the policy-as-code, the control mapping, the ConMon trend) so the assessment team can evaluate it; supply-chain controls (SR-2/3/4/11 + SBOM/provenance/signing) align to 800-161r1 / 800-204D |

---

## Practical "what to assemble for a cATO request" checklist (using this repo)

1. **Prerequisite:** the system already has an ATO and is in the RMF **Monitor** step. (This repo's evidence supports getting and keeping that ATO.)
2. **Pillar 1 evidence:** the GitHub Pages dashboard URL + the ATO Status issue + `evidence/boe/conmon_history.json` + `controls.json`/`controls_summary.json` + `policy/thresholds.yaml` (risk thresholds/SLAs) + the daily-schedule pipeline runs. (CA-7.)
3. **Pillar 2 evidence (from your SOC/CSSP — not this repo):** CSSP agreements; runtime IDS/IPS/EDR; threat-intel ingestion; real-time countermeasure deployment; incident-response plan + exercise records; indicator sharing; JFHQ-DODIN/USCYBERCOM coordination. (SI-4, AU-6, IR-4/IR-6.) Cross-reference the repo's SI-2/SI-3/SI-4 evidence as the vulnerability-management half.
4. **Pillar 3 evidence:** which **approved DoD Enterprise DevSecOps Reference Design** the platform aligns to (cite it); the dev/test/staging environments; this pipeline (the guardrails/control gates — `devsecops-pipeline.yml`); the Secure Software Supply Chain artifacts (SBOMs, SLSA provenance, cosign signatures, OpenSSF Scorecard, pinned deps); the DevSecOps Activities & Tools mapping (`devsecops-reference-design-crosswalk.md`). (SA-3, SA-15, SR-3/4/11, CM-8.)
5. **Risk governance:** the org's risk management strategy (PM-9) and the acceptable-residual-risk tolerances feeding `policy/thresholds.yaml`.
6. **Package & route:** the AO + Component CISO present the BoE to the **DoD CISO** for the cATO decision. Use `evidence/emass-package/` + the dashboard as the BoE; track the milestone via the ATO milestone issue template.
7. **Maintain it:** keep the pipeline green/daily; keep the dashboard current; close POA&M items within SLA (cATO is revocable for poor cyber posture). Report metrics (MTTP, etc.) per the AO's expectations.

---

## What this repo does **not** claim about cATO

- It does **not** make you cATO-eligible by itself. cATO requires a prior ATO, the Monitor step, an approved Reference-Design platform, the active-cyber-defense capability, and a DoD-CISO decision.
- It does **not** provide the **active cyber defense** pillar — that's your SOC/CSSP + runtime defenses + the JFHQ-DODIN/USCYBERCOM relationship.
- It does **not** monitor inherited/common controls — the platform/RPOC/CSP does; this repo covers the application + pipeline.
- The automated control test results are a **first pass**; the SCA makes the final determination and signs the SAR; the AO (and DoD CISO for cATO) renders the authorization decision.
