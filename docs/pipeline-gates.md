# Pipeline gates — tool, controls, pass/fail policy, evidence path

Each gate is a job in `.github/workflows/devsecops-pipeline.yml` (or a standalone workflow). The
fail-the-build policy is centralized in `policy/thresholds.yaml`; tool config is in `policy/`.
Evidence is uploaded as a workflow artifact named `evidence-<gate>` and consolidated by the
`body-of-evidence` job into `evidence/<gate>/` + `evidence/findings.json`.

| Gate (job) | Tools | NIST 800-53 | SSDF | RAISE Gate | Build-blocking when | Evidence |
|---|---|---|---|---|---|---|
| **build-test** | pytest + coverage, ruff (advisory) | SA-3, SA-11, SA-15 | PW.6, PW.8 | — | tests fail; coverage < floor | `test-results.xml`, `coverage.xml` |
| **sast-semgrep** + **codeql.yml** | Semgrep (registry rulesets + `policy/semgrep/dod-secure-coding.yml`), CodeQL (`security-extended` + `security-and-quality`) | SA-11(1), SA-15(7), RA-5 | PW.7 | **1** | new Critical/High (diff-aware); pre-existing → POA&M | SARIF → GitHub code scanning; `evidence/sast/**` |
| **sca-dependencies** | Trivy fs, Grype, OWASP Dependency-Check | RA-5, SI-2, SA-22 | PW.4, RV.1 | **2** | Critical CVE, or High with a fix; unfixed Critical also fails | `evidence/sca/**` (+ SARIF) |
| **sbom-source** (+ image SBOM in `container`) | Syft → SPDX 2.3 + CycloneDX 1.5 | CM-8, SR-3, SR-4 | PS.3 | **2** | (always produced; structurally checked vs NTIA minimum elements — informational) | `evidence/sbom/**`; Release assets; cosign attestation on the image |
| **secrets-scan** | Gitleaks, TruffleHog (+ Trivy/Semgrep secret rules + GitHub push protection) | IA-5, SI-3 | PS.1 | **3** | any verified / high-confidence secret | `evidence/secrets/**` |
| **iac-scan** | Checkov, KICS, Trivy config, kube-linter, Conftest/OPA (`policy/opa/*.rego`) | CM-2/CM-6, CM-7, SC-7, AC-3 | PW.9 | (expected practice — not a named RIG gate) | Critical/High; any Rego `deny` | `evidence/iac/**` (+ SARIF) |
| **license-compliance** | CycloneDX SBOM + `scripts/evidence_common.py --check-licenses` vs `policy/allowed-licenses.yaml` | CM-10 | PW.4 | **2** (component analysis) | a disallowed license; review-required → POA&M | `evidence/license/**` |
| **container** | docker buildx, Trivy (image), Grype, Hadolint, Dockle, Syft (image SBOM), cosign/Sigstore, `actions/attest-build-provenance` (SLSA), push to GHCR | RA-5, CM-6, CM-7, SI-2, SI-7, SR-4, SR-11, AC-6 | PW.6, PW.9, PS.2, PS.3 | **4, 7, 8** | Critical image CVE, or High with a fix; FATAL hardening (Dockle/Hadolint); not non-root; no healthcheck | `evidence/container/**`; signed image + SBOM + SLSA attestations in GHCR; `evidence/provenance/**` |
| **dast** | OWASP ZAP baseline (`policy/zap/rules.tsv`) vs the running image | SA-11(8), CA-8 | PW.8 | **5** | ZAP High alert; Medium/Low → POA&M | `evidence/dast/**` |
| **stig-scap** | OpenSCAP (XCCDF eval) + `.ckl` skeleton — **supply your DISA STIG/SRG SCAP content** | CM-6 | PW.9 | (DISA Container Platform SRG / Kubernetes STIG) | open CAT I STIG finding; CAT II/III → POA&M | `evidence/stig/**` (results XML, report HTML, `.ckl`) |
| **openssf-scorecard** (`openssf-scorecard.yml`) | OpenSSF Scorecard | SR-3, SA-15, CM-3, CM-5 | PO.3, PO.5 | — | (reported; weak checks → findings/POA&M candidates) | `evidence/scorecard/**` (+ SARIF) |
| **review** (branch protection + CODEOWNERS + ATO Status issue + dashboard) | GitHub PR review, `dependabot-auto` triage | CM-3, CM-4, CM-5, CA-6, AC-6 | PW.2, PS.1 | required Code Owner review missing; required checks failing | PR review history; ATO Status issue; dashboard |
| **body-of-evidence** | `aggregate_evidence.py` → `map_controls.py` → `generate_poam.py` → `update_conmon.py` → `build_emass_package.py` → `build_dashboard_data.py` | CA-2, CA-5, CA-7, PL-2, RA-3 | PO.4, RV.1, RV.2 | (RAISE quarterly-review artifacts) | (always runs; assembles `evidence/`, the dashboard, the eMASS package) | `evidence/findings.json`, `evidence/boe/*`, `evidence/sbom/*`, `evidence/emass-package/*`, `site/data/*` |

## Notes per gate

### sast
- CodeQL runs in `codeql.yml` so results land in GitHub code scanning natively; Semgrep runs in the main pipeline and also uploads SARIF. Add languages to the `codeql.yml` matrix for your workload.
- Diff-aware: CodeQL PR analysis and Semgrep's diff mode flag *newly introduced* findings as build-blocking; pre-existing findings are recorded and go to the POA&M. Tune in `policy/thresholds.yaml: gates.sast.new_findings_only`.

### sca / container vulnerabilities
- Three SCA tools (Trivy/Grype/Dependency-Check) for coverage breadth; results are deduplicated by the aggregator. Critical = always block; High = block if a fix exists, else POA&M (configurable). Suppress only via `policy/trivy/.trivyignore` / `.trivyignore.xml` with a documented justification + review date — the SCA reviews those files.
- In IL4/IL5/air-gapped, point the scanners' vulnerability DBs at internal mirrors and pre-load them; see `impact-level-notes.md`.

### sbom
- Two formats (SPDX 2.3 and CycloneDX 1.5), for both the source tree and the built image. Validated against the NTIA "Minimum Elements for an SBOM" (Author, Timestamp, Component name/version/ID, Dependency relationships) — informational. The CycloneDX image SBOM is also attached to the image as a cosign attestation.

### container / signing / provenance
- Multi-stage build (build tools never reach the runtime image), pinned base (prefer Iron Bank by digest), non-root user, healthcheck, OCI provenance labels. Hadolint lints the Dockerfile; Dockle checks CIS/best-practice. The image is signed keyless via Sigstore (recorded in the Rekor transparency log) and gets a SLSA build-provenance attestation via `actions/attest-build-provenance` — pushed to GHCR alongside the image. RAISE Gate 7 (sign) + Gate 8 (store in an artifact repo) + the RPOC's admission control (verify signature before deploy) close the loop.

### stig
- **This gate ships a placeholder.** It demonstrates an OpenSCAP evaluation flow using whatever SCAP content is bundled in the `ghcr.io/oscap/openscap-scanner` image. **You must supply the appropriate DISA SCAP benchmark / STIG content for your actual base OS / container platform** — get it from the DoD Cyber Exchange (`public.cyber.mil`, e.g., the relevant OS STIG, the Container Platform SRG, the Kubernetes STIG). Mount your content and point `oscap xccdf eval` at it. The gate also emits a `.ckl` skeleton (`scripts/evidence_common.py --scap-to-ckl`); for a full STIG checklist use `oscap`'s STIG-Viewer output or STIG Viewer itself. If you base your image on an Iron Bank hardened image, much of the OS STIG burden is inherited (cite the image's hardening manifest / inherited-controls appendix).

### dast
- Baseline (passive + a quick active spider) against the locally-run container. For deeper coverage, add a full ZAP scan (`zaproxy/action-full-scan`) with authenticated context, an OpenAPI/GraphQL spec, and a longer time budget — coordinate with your CSSP and treat it as active testing (rules of engagement). Pen testing at the AO-defined frequency satisfies CA-8.

### body-of-evidence
- This job downloads every `evidence-*` artifact, normalizes all SARIF/JSON/XML/CKL into `evidence/findings.json` (deduplicated, severity-rated), maps findings + gate coverage to controls (`evidence/boe/controls.json`), generates the POA&M (`evidence/boe/poam.csv`), appends a ConMon snapshot (`evidence/boe/conmon_history.json`), assembles the eMASS package (`evidence/emass-package/`), and writes the dashboard data (`site/data/*.json`). On `release: published` it attaches the eMASS package + key CSVs/SBOMs to the Release.
