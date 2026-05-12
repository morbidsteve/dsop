# Information Security Continuous Monitoring (ISCM) Strategy — (REPLACE) DSOP Reference System

The **CA-7** artifact. Also the basis for **cATO Pillar 1** (continuous monitoring of RMF controls)
and the **RAISE 2.0 ConMon** expectation, and it supports the Application Owner's **Vulnerability
Management Plan** (RAISE App-Owner artifact). Authoritative basis: NIST SP 800-137 (ISCM), NIST SP
800-37 Rev 2 (Monitor step), DoDI 8510.01, the cATO memo/Implementation Guide, RAISE 2.0 RIG. Tailor
the placeholders.

---

## 1. Objectives

Maintain ongoing awareness of the system's security posture and risk so the AO/ISSM/SCA can make
**near-real-time risk decisions** — not point-in-time. Specifically:
- Re-assess all **automatable** controls continuously (on every change and at least daily).
- Detect new vulnerabilities/weaknesses fast and drive them to remediation within defined SLAs.
- Keep the Body of Evidence (control status, POA&M, findings, SBOM) current and exportable to eMASS.
- Provide a **system-level dashboard** and an always-current status view (the ATO Status issue).
- Feed the RPOC's near-real-time risk view (RAISE) and support cATO maintenance.

## 2. What is monitored, by whom, how often

| Layer | What | Mechanism | Frequency | Owner |
|---|---|---|---|---|
| **Application code** | SAST findings, secure-coding-rule violations, secrets, license policy | CodeQL, Semgrep (+ DoD rules), Gitleaks, TruffleHog, GitHub secret scanning/push protection, license policy check | Every push/PR + daily + on demand | Application Owner (pipeline) |
| **Dependencies** | Known-vulnerable components, EOL/unsupported components, license risk | Trivy fs, Grype, OWASP Dependency-Check, Syft SBOM, Dependabot | Every push/PR + daily; Dependabot daily | Application Owner |
| **Container image** | OS/library CVEs, hardening (non-root, minimal, healthcheck), config | Trivy (image), Grype, Hadolint, Dockle | Every build + daily | Application Owner |
| **IaC / config** | Misconfigurations, policy violations | Checkov, KICS, Trivy config, kube-linter, Conftest/OPA | Every push/PR + daily | Application Owner |
| **Runtime app / API** | Web vulnerabilities, missing security headers | OWASP ZAP baseline (DAST) against the running image | Every build + daily | Application Owner |
| **STIG / SCAP** | Configuration compliance vs. DISA SRG/STIG | OpenSCAP (supply your DISA SCAP content) | Every build + daily; full STIG review per AO cadence | Application Owner (+ inherited from Iron Bank base) |
| **Supply-chain / repo hygiene** | Branch protection, code review, pinned deps, signed releases, dangerous workflows, token permissions | OpenSSF Scorecard | Weekly + on push + on branch-protection change | Application Owner |
| **Build provenance / integrity** | Image signature validity, SLSA provenance, signed commits | cosign verify (admission), `actions/attest-build-provenance`, signed-commit policy | Every release + at admission | Application Owner (build) / RPOC (admission) |
| **Control posture** | Per-control implementation status + test result; assessment coverage | `map_controls.py` → `controls.json` / dashboard | Every pipeline run | Application Owner; **SCA validates** |
| **POA&M** | Open items, scheduled completion dates, overdue, out-of-RAISE-scope | `generate_poam.py` → `poam.csv`/`.json` / dashboard | Every pipeline run | Application Owner / ISSM |
| **Trend / metrics** | Findings by severity over time, control results trend, POA&M open/overdue, mean-time-to-patch, SBOM component count | `update_conmon.py` → `conmon_history.json` / dashboard ConMon view | Every pipeline run | Application Owner |
| **Runtime infrastructure** | Host/cloud vulnerability scans, network monitoring, IDS/IPS/EDR, log analytics/SIEM, threat hunting | **Platform / RPOC / CSP** (inherited/common) — and the basis for cATO's active-cyber-defense pillar (operations-side) | Per the platform's ConMon plan | RPOC / CSP / CSSP |
| **Personnel / physical / training** | Account reviews, physical controls, training currency | (REPLACE — program/common controls) | Per policy | Program / common control provider |

## 3. Thresholds, SLAs, and escalation

Defined in `policy/thresholds.yaml`:
- **Build-blocking gates:** new Critical/High SAST; any verified secret; Critical container/dep CVE (or High with a fix); disallowed license; ZAP High; open CAT I STIG; Rego deny; failed tests. (Tunable.)
- **POA&M generation:** findings ≥ the configured min severity that aren't build-blocking → POA&M with `Scheduled Completion Date = first_seen + sla_days[severity]`.
- **Remediation SLAs (default):** Critical/High (CAT I) = **21 calendar days** (RAISE: raw High+ in production); Medium (CAT II) = 90 days; Low (CAT III) = 365 days. **Adjust to your AO's policy.**
- **Overdue:** flagged red on the dashboard / called out in the ATO Status issue. For RAISE, a production workload with an unremediated High+ finding past 21 days is **isolated/removed** by the RPOC ISSM (with the App Owner) pending an **AO exception** — request via the control-deviation/risk-acceptance issue template.
- **Out-of-RAISE-scope:** any finding whose residual risk would exceed **Moderate** → flagged "AO escalation required" (High-risk apps are out of RAISE scope and must use normal RMF).
- **Significant change:** triggers SSP/PPSM updates, a security impact analysis (CM-4, via the PR template), and ISSM/SCA notification; re-assessment is automatic on the change's PR.

## 4. Reporting cadence

| Audience | What | When |
|---|---|---|
| AO / ISSM / SCA | The GitHub Pages dashboard (live); the ATO Status issue (refreshed on each pipeline run + weekly) | Continuous |
| RPOC ISSM (RAISE) | The eMASS package link + the dashboard (the app's contribution to the RPOC's near-real-time view); High+ mitigation statements before each release | Per release + on request |
| SCA + AO (RAISE quarterly review) | The eMASS package (controls + test results + POA&M + artifacts) = the app's quarterly-review packet; SCA signs the SAR before the AO meeting; AO sets the next review date | Quarterly (cadence may relax once a working relationship is established; per the AO) |
| AO (RAISE annual review) | Full BoE review of the RPOC + incorporated apps | Annually |
| DoD CISO (cATO) | The BoE (presented by the AO + Component CISO); ongoing metrics per the AO's expectations | At cATO decision + as required (cATO has no expiration but is revocable) |
| FISMA / CIO metrics | Derived from `controls_summary.json` / `conmon_history.json` (and eMASS's built-in dashboards) | Per organizational reporting cycle |

## 5. Edge / disconnected operations (RAISE)

If a production node cannot perform ConMon itself (ships, submarines, aircraft, tactical/edge,
air-gapped): the **ConMon requirement is met at the Staging/Pre-Prod tier** (run the full pipeline +
ConMon there), and the edge node **synchronizes** logs/updates with Staging as the mission allows.
Document the sync mechanism, frequency, and the handling of findings discovered while disconnected
here. (For IL4/IL5/air-gapped pipelines generally, see `docs/impact-level-notes.md` — internal
tool/DB mirrors, self-hosted runners, Iron Bank tooling images.)

## 6. ConMon program management

- **Strategy review:** this document is reviewed at least annually and on significant change. (REPLACE owner/date.)
- **Tooling currency:** scanner vulnerability databases and rulesets are kept current automatically (or via internal mirrors for IL4/IL5); GitHub Actions and the scanners themselves are updated via Dependabot.
- **Effectiveness:** the ConMon trend, the POA&M overdue count, and mean-time-to-patch are the headline effectiveness metrics; review them at each quarterly review. If the pipeline is repeatedly red, or the backlog grows, escalate to the ISSM/AO and consider tightening change control or pausing deployments.
- **Records:** `conmon_history.json` (the trend), the per-run `body-of-evidence` artifacts (365-day retention), and the GitHub Releases (the eMASS packages per version) constitute the ConMon record.
