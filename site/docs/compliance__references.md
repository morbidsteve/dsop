# Governing policy & frameworks — annotated bibliography

This is the authority list behind everything in `compliance/` and `policy/`. **Confirm the current
version of each against the controlling source for your program** — several authoritative artifacts
are CAC-restricted and may be newer than the public versions cited here. Where this repo is
uncertain, it says so (look for ⚠️).

> Maintenance: when you adopt this template, replace the placeholder system facts (in
> `control-catalog.yaml` and `system-security-plan.md`) and re-confirm every document version. Add
> a dated note here whenever you verify or supersede an entry.

---

## 1. NIST Risk Management Framework & control catalog

| Doc | What it is | Use here |
|---|---|---|
| **NIST SP 800-37 Rev 2** — *Risk Management Framework for Information Systems and Organizations* (Dec 2018) | The 7-step RMF: **Prepare → Categorize → Select → Implement → Assess → Authorize → Monitor**. Defines the BoE artifacts (SSP, SAP, SAR, POA&M, authorization decision, ConMon strategy) and roles (AO, SCA, ISSM, ISSO, SO/PM, etc.). | RMF-step framing in the SSP & crosswalks; the "Monitor" step is the basis for ConMon / cATO. |
| **NIST SP 800-53 Rev 5** (+ updates) — *Security and Privacy Controls for Information Systems and Organizations* (Sept 2020) | The control catalog: 20 families incl. the Rev-5 additions **SR** (Supply Chain Risk Management) and **PT** (PII Processing & Transparency). | Source of every control in `control-catalog.yaml`. |
| **NIST SP 800-53B** — *Control Baselines* | Low/Moderate/High baselines + the privacy baseline (for federal systems; NSS/DoD use CNSSI 1253 baselines built from the same controls). | Reference for which controls are "in baseline". |
| **NIST SP 800-53A Rev 5** — *Assessing Security and Privacy Controls* | Assessment procedures: per-control **assessment objectives → determination statements**, **methods** (Examine / Interview / Test), and **objects**. Exposed in eMASS as Assessment Procedures (APs). | `assessment.methods` / `assessment.objective` fields in the catalog; the SCA's SAP/SAR. |
| **NIST SP 800-30 / 800-39 / 800-137** | Risk assessment; org-wide risk management; **Information Security Continuous Monitoring (ISCM)**. | ConMon strategy; risk language in the POA&M. |
| **CNSSI No. 1253** — *Categorization and Control Selection for National Security Systems* (current public version dated 29 Jul 2022 — ⚠️ verify on cnss.gov) | How NSS/DoD categorize (independent **C-I-A** Low/Moderate/High, not a single high-water mark) and which baselines/overlays to use; the NSS counterpart to FIPS 199/200 + 800-53B. | Categorization in the SSP/catalog metadata; overlay selection. |
| **DoD RMF Knowledge Service** — `rmfks.osd.mil` (⚠️ CAC-restricted) | DoD-specific overlays, assignment values, "Assess Only" procedures, authorization-decision definitions, and the **cATO Evaluation Criteria**. Maintained by the **RMF Technical Advisory Group (TAG)**. | The authoritative source for DoD-tailored control parameters — tailor the catalog to match. |
| **CMMC / NIST SP 800-171 Rev 2 (+ 800-171A); SP 800-172** (and SP 800-171 **Rev 3** — finalized May 2024 but ⚠️ not yet DoD-adopted for CMMC/SPRS scoring) | Protection of CUI in nonfederal (contractor) systems; the basis for **CMMC 2.0** levels. | Only if your repo/program is also subject to CMMC; map 800-171 reqs to the relevant 800-53 controls. |

## 2. DoD RMF & cybersecurity policy

| Doc | What it is | Use here |
|---|---|---|
| **DoDI 8510.01**, *Risk Management Framework for DoD Systems* — current reissuance **19 Jul 2022** (supersedes the 2014 version + DTM 20-004; ⚠️ check the RMF KS for any interim change) | Establishes RMF for DoD systems; assigns roles; charters the RMF TAG; adopts NIST RMF/800-37; directs categorization & control selection per **CNSSI 1253** with DoD overlays; supports **ongoing authorization**. Authorization package minimum (Table 6): **security plan/SSP, SAR, all POA&Ms, authorization decision document**. | The DoD RMF authority; role definitions; package contents. |
| **DoDI 8500.01**, *Cybersecurity* (Mar 2014, incl. Change 1) | The umbrella cybersecurity policy; defines ISSM/ISSO and the cybersecurity program. | Role definitions; program context. |
| **DoD Cybersecurity Reciprocity Playbook** (DoD CIO; cover-dated ~2 Jan 2024) | How to reuse another AO's BoE / inherited authorizations (relevant to RAISE control inheritance and cATO Use Case 2). | Inheritance / CRM language. |
| **CNSSP / CNSSI series** (e.g., CNSSI 1253 overlays for cross-domain, classified, intel, space, privacy) | NSS-community overlays. | Apply the ones your categorization/community requires. |

## 3. Continuous ATO (cATO)

| Doc | What it is | Use here |
|---|---|---|
| **DoD CIO memo, "Continuous Authorization To Operate (cATO)"** — ~**3 Feb 2022** (signed by the DoD SISO) | Establishes cATO as the "gold standard." An AO must demonstrate **three competencies**: (1) **continuous monitoring of RMF controls** (near-real-time, all controls, system-level dashboard for real-time AO risk decisions across the AOR); (2) **active cyber defense** ("scans and patching" alone is *not* enough — constant comms with CSSPs / Component cyber forces / JFHQ-DODIN / USCYBERCOM, ingest threat intel, deploy countermeasures in real time); (3) **adoption of an approved DoD Enterprise DevSecOps Reference Design** + a **Secure Software Supply Chain** (incl. SBOM) — often summarized as the **3 (+1) pillars**. cATO is granted at the **DoD CISO** level, requires a prior ATO and being in the RMF Monitor step, **has no expiration**, and is **revocable**. | The target end-state; see `crosswalks/cato-evaluation-crosswalk.md`. |
| **DoD CIO, "DevSecOps Continuous Authority to Operate — Evaluation Criteria"** (cleared **18 Dec 2023**) | The assessment criteria for evaluating a cATO request from a software factory; defines the **two cATO use cases** (UC1 inside the DSOP boundary; UC2 outside it) and how factories build & submit a cATO package; references **NIST SP 800-161r1**. Posted on the RMF KS / DoD CIO Library. | Maps "what an assessor checks" to this repo's evidence. |
| **DoD CIO, "DevSecOps Continuous Authorization Implementation Guide"** — **v1.0, Mar 2024** (cleared 11 Apr 2024; **Distribution Statement C** — not unrestricted public) | Operationalizes cATO: defines a **software factory** (DSOP + people + process + cloud, ≥ dev/test/staging), the required **guardrails & control gates collecting continuous evidence**, dashboards/alerts, the risk-governance feed of acceptable residual-risk tolerances, the assessment method (assess the platform + process + people, periodically), and **continuous-authorization metrics** (Mean Time to Patch, guardrail/gate trend metrics, etc.). | The detailed cATO playbook the crosswalk maps to. |

## 4. DoD Enterprise DevSecOps

| Doc | What it is | Use here |
|---|---|---|
| **DoD Enterprise DevSecOps Reference Design** — original v1.0 (12 Aug 2019), now a family of designs: **CNCF Kubernetes**, **CNCF Multi-Cluster Kubernetes** (v1.0, Jul 2022), **AWS Managed Services** (19 Oct 2021), plus others via the **"Pathway to a Reference Design"** (18 Oct 2021). | The reference architectures for a "software factory" / DSOP: the **Infrastructure / Platform-(Software Factory) / Application** layering, **Reference Design Interconnects**, hardened-container service, control gates. Adoption of an *approved* one is cATO pillar 3 and a RAISE assumption. | `crosswalks/devsecops-reference-design-crosswalk.md`. |
| **DoD Enterprise DevSecOps Fundamentals** — v2.x (e.g., v2.5, Oct 2024) | The 10-phase DevSecOps lifecycle (**Plan, Develop, Build, Test, Release, Deliver, Deploy, Operate, Monitor, Feedback**) + the "software factory" concept + continuous-monitoring definitions. | Lifecycle framing for the pipeline & gates. |
| **DevSecOps Fundamentals Guidebook: DevSecOps Activities & Tools** — v2.x (e.g., v2.5, Apr 2025) + companion spreadsheet | Per-phase activities and tool taxonomy; the spreadsheet is explicitly "a template for building a continuous ATO package that demonstrates process and responsibility mapping." | Gate ↔ activity mapping; tool selections in `policy/`. |
| **DevSecOps Playbook** (DoD CIO, v2.1, Sept 2021) | Practical guidance; references Platform One / authorized platforms with integrated cATO practices. | Background. |
| **DoD CIO, "The State of DevSecOps"** (Mar 2025) | Survey of the DoD software-factory ecosystem & governance. | Background. |
| **DoD Software Modernization Strategy (2022)** + **Software Modernization Implementation Plan (FY25-26)** | Strategic drivers — "accelerate software delivery with continuous authorization." | Strategic context for the SSP intro. |

## 5. U.S. Navy — RAISE 2.0

| Doc | What it is | Use here |
|---|---|---|
| **Rapid Assess and Incorporate Software Engineering (RAISE) 2.0 Implementation Guide ("RIG")** — **Version 1.0, "As Released" 4 Oct 2022** (DON CIO / DON CISO; authored by the RAISE Working Group; NAVWAR led development). Published with the **joint DON CISO / DDCISO-Navy / DDCISO-USMC memo dated 1 Nov 2022** (signed off by the DON SISO). ⚠️ Confirm the current version on `doncio.navy.mil/ciso`; DON has signaled future updates (non-containerized apps, more automation, "RAISE as a Service"). | RAISE 2.0 lets a **containerized** application be **incorporated into the existing ATO of an authorized DevSecOps platform** (a **RAISE Platform of Choice / RPOC**) instead of getting its own ATO: control inheritance + Customer Responsibility Matrix, AO **delegates assessment authority to the RPOC ISSM**, continuous pipeline evidence + **quarterly reviews** with the SCA/AO + annual AO review of the RPOC. Defines: the **8 Security Gates** (1 SAST, 2 Dependency list/SBOM, 3 Secrets/keys detection, 4 Container security scanning, 5 DAST, 6 RPOC-ISSM-review step, 7 sign the release container image, 8 store the release image in an artifact repository); the **24 "RPOC #" requirements**; the **Application-Owner artifacts** (Vulnerability Management Plan, architecture diagram, README, CHANGELOG/release notes, aggregated SAST/DAST/Container/Dependency results, mitigation statements, SRG+STIG, SCF, PIA, DADMS+DITPR-DON IDs, signed SLA, Release Plan); the **quarterly-review (QREV) items**; residual risk **must not exceed Moderate**; raw **High+ findings in production remediated/mitigated within 21 calendar days** (else isolate/remove the workload pending AO exception); High+ mitigations reviewed by a **Qualified Validator / Independent Assessor**; **edge/disconnected** environments meet ConMon at the Staging tier. The **DSOP→RPOC transition** requires the AO to approve the platform's inheritable controls (RMF Step 2) **and** the **Technical Authority** to certify the CI/CD pipeline tools (per the **DevSecOps CI/CD Assessment Guidebook v1.0**), after which the AO updates the platform's **Authorization Decision Document** to confer RPOC status. RAISE is tied to the DON **"Cyber Ready"** initiative. ⚠️ The RIG v1.0 does **not** enumerate IaC scanning or a standalone OSS-license gate as named gates (this repo runs them anyway as expected practice), and does **not** separately define ISSO/ISSE roles (it uses CIO/SISO, AO, SCA, TA, RPOC Owner, RPOC ISSM, Application Owner). | The primary Navy authority; see `crosswalks/raise-2.0-crosswalk.md`. |
| **DevSecOps CI/CD Assessment Guidebook** (v1.0, Jun 2021) — referenced by the RIG | The criteria the **Technical Authority** uses to certify an RPOC's CI/CD pipeline tools for "usability and functional capability." | Background for the TA tool-certification step. |
| **DON Strategic Intent for Software Modernization** (Aug 2021); **DON "Cyber Ready"** material | Navy strategic drivers behind RAISE. | SSP intro context. |
| **NAVWAR / NIWC Pacific — Overmatch Software Armory (OSA)** | The pilot platform that demonstrated RAISE requirements and earned RPOC designation (PEO Digital / NAVWAR). | Real-world RPOC example (if your app deploys onto it). |
| DON CIO RAISE artifacts page — `https://www.doncio.navy.mil/ciso` (⚠️ some artifacts/templates CAC-restricted) | Templates, the Navy RMF Process Guide referenced in RIG Appendix D. | Where to get current RAISE artifacts. |

## 6. Containers, STIGs, hardening

| Doc | What it is | Use here |
|---|---|---|
| **NIST SP 800-190** — *Application Container Security Guide* | Container threats & countermeasures. | Container gate rationale; CM-6/CM-7 narratives. |
| **DISA Container Platform Security Requirements Guide (SRG)** (initial release Dec 2020) + **Kubernetes STIG** (Apr 2021) | The SRG/STIG governing container platforms (orchestrators, runtimes, registries). | STIG/SCAP gate; CM-6; `deploy/k8s/` hardening. |
| **DoD/DISA Container Hardening Process Guide** — **V1R2, 24 Aug 2022** (a.k.a. "DevSecOps Enterprise Container Hardening Guide" v1.1/1.2; V1R1 Oct 2020) | Defines **DoD Hardened Containers**, the **DoD Container Factory**, **Repo One** (`repo1.dso.mil` — source/Dockerfiles/hardening manifests), **Iron Bank** (DCAR — approved hardened images), the hardening pipeline (vuln scan + STIG/SRG compliance via Chef InSpec/OpenSCAP + Findings Mitigation Report), and the **inherited security controls** consuming programs get from using Iron Bank images. | Base-image guidance in the Dockerfile / `policy/opa/container_image.rego`; control inheritance. |
| **Platform One / Iron Bank / Repo One / "Party Bus"** | The Air-Force-operated enterprise DevSecOps MSP, hardened-image registry, source repo, and managed CI/CD/hosting offering (the canonical cATO UC1 example). | Reference for "authorized to use" platforms. |
| **DoD Cyber Exchange** — `public.cyber.mil` / `cyber.mil` | Where DISA SRGs/STIGs, SCAP benchmark content, and STIG Viewer live (⚠️ some pages now require CAC). | Source the actual STIG/SCAP content for your `stig-scap` gate from here. |

## 7. Software supply chain

| Doc | What it is | Use here |
|---|---|---|
| **Executive Order 14028** — *Improving the Nation's Cybersecurity* (12 May 2021), §4 | Software supply chain provisions; directed the SSDF, the SBOM minimum elements, "critical software," and the agency SBOM/attestation requirement. | Driver for SBOM + SSDF in the pipeline. |
| **NTIA "The Minimum Elements for an SBOM"** (Jul 2021); **CISA SBOM guidance** ("Framing Software Component Transparency" 3rd ed. Oct 2024; VEX minimum requirements; SBOM sharing lifecycle; ⚠️ a 2025 "Minimum Elements" update is in draft) | SBOM **data fields** (Supplier, Component, Version, Other Unique IDs (CPE/SWID/PURL), Dependency Relationship, Author of SBOM Data, Timestamp) + **Known Unknowns**; **automation support** in **SPDX / CycloneDX / SWID**; **practices** (Frequency = per release, Depth, Distribution, Access Control). | `scripts/evidence_common.py --validate-sbom`; the SBOM gate produces SPDX 2.3 + CycloneDX 1.5. |
| **NIST SP 800-218 — Secure Software Development Framework (SSDF) v1.1** (Feb 2022) | Outcome-based secure-dev practices in 4 groups: **PO** Prepare the Organization, **PS** Protect the Software, **PW** Produce Well-Secured Software, **RV** Respond to Vulnerabilities. (Plus **SP 800-218A** for GenAI; a draft v1.2.) | `crosswalks/ssdf-800-218-crosswalk.md`. |
| **OMB M-22-18 / M-23-16** + **CISA "Secure Software Development Attestation Form"** (Common Form, finalized Mar 2024) + the **Repository for Software Attestations and Artifacts (RSAA)** | Agencies must obtain a producer self-attestation of conformity to SSDF practices (and sometimes an SBOM / 3PAO assessment / POA&M). | If your software is delivered to a federal agency, the pipeline's SSDF evidence supports the attestation. |
| **NIST SP 800-161 Rev 1** — *Cybersecurity Supply Chain Risk Management Practices*; **NIST SP 800-204D** — *Integrating Software Supply Chain Security in DevSecOps CI/CD Pipelines* | C-SCRM controls; CI/CD supply-chain integration patterns. | SR-family narratives; pipeline supply-chain controls. |
| **SLSA (Supply-chain Levels for Software Artifacts) v1.0** (OpenSSF, 2023) | Build track L0–L3 (L1 provenance exists; L2 hosted build + signed provenance; L3 hardened/isolated). Provenance = in-toto attestation (`slsa.dev/provenance/v1`), DSSE-signed, often via Sigstore (cosign/Fulcio/Rekor). | Container gate's `actions/attest-build-provenance` + cosign; SR-4 evidence. |
| **CISA/NSA/ODNI ESF "Securing the Software Supply Chain — Recommended Practices"** — Developers (2022), Suppliers (2022; 2024 update), Customers (2022) | Recommended practices for secure development, build/release environments, third-party/OSS management, vuln handling, SBOM use. | Background for the SSDF crosswalk and `policy/`. |

## 8. Acquisition context (informational)

| Doc | What it is |
|---|---|
| **DoDI 5000.87**, *Operation of the Software Acquisition Pathway* (2 Oct 2020) — implements §800 of the FY2020 NDAA | Tailored acquisition pathway for custom software (Planning + Execution phases; iterative/Agile/DevSecOps delivery; deliver capability ≤ 1 yr then ≥ annually; cybersecurity/program protection per RMF throughout — the natural fit for cATO). |
| **DoDI 5000.83** (Technology & Program Protection); **DoDI 5000.90** (Cybersecurity for Acquisition Decision Authorities); **DoDI 5000.82** (Acquisition of IT); **DoDI 5000.89** (T&E) | The surrounding Adaptive Acquisition Framework issuances. |

---

### Quick "where to confirm the current version" pointers
- DoD RMF / overlays / cATO Evaluation Criteria → **RMF Knowledge Service** `rmfks.osd.mil` (CAC).
- DoD CIO DevSecOps & cATO docs → **DoD CIO Library** `dodcio.defense.gov/library`.
- DISA SRGs/STIGs/SCAP & STIG Viewer → **DoD Cyber Exchange** `public.cyber.mil`.
- Navy RAISE 2.0 artifacts → **DON CIO CISO page** `doncio.navy.mil/ciso` (some CAC).
- eMASS user guide / POA&M import template → your eMASS instance's help / the DISA RMF portal / DCSA NISP-eMASS pages (CAC).
- NIST publications → `csrc.nist.gov`. NTIA/CISA SBOM → `ntia.gov`, `cisa.gov/sbom`. SLSA → `slsa.dev`.
