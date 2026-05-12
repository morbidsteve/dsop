# Impact Level notes — IL2 (GitHub.com) vs. IL4/IL5 (GitHub Enterprise Server / DoD enclave)

This repo is scaffolded for **IL2 / GitHub Enterprise Cloud (github.com)** — public Actions,
CodeQL/GHAS, Sigstore (public Fulcio/Rekor), GHCR, and public action/tool sources. To run it in an
**IL4/IL5 DoD enclave on GitHub Enterprise Server (GHES)** (or any air-gap-adjacent environment),
apply these deltas. Confirm everything against your enclave's accreditation and the **DoD Cloud
Computing SRG** impact-level requirements.

## Runners
- **Self-hosted runners** in the enclave (not GitHub-hosted). Harden them per CM-6 (STIG the runner host), run them ephemerally, and scope their network egress (CM-7/SC-7). For GHES, deploy the Actions runner controller / VM scale sets in your accredited environment.
- No outbound internet from runners — every tool/DB/action must come from an internal source (below).

## Actions sourcing
- **Pin every `uses:` to a full commit SHA**, not a tag (the `# IL4/IL5` note at the top of `devsecops-pipeline.yml` already says this — do it). Tags are mutable; SHAs aren't.
- Mirror the actions you use into an **internal GitHub org / GHES** (or vendor them) and reference the mirror. Enable an **Actions allow-list** at the org/enterprise level (only approved actions can run). The OpenSSF Scorecard "Pinned-Dependencies" / "Dangerous-Workflow" checks help you enforce this.
- For actions that download tools at runtime (`anchore/sbom-action` pulls Syft, `aquasecurity/trivy-action` pulls Trivy, the Grype/Conftest/Dockle `curl` steps, the OpenSCAP container image): replace those with pre-installed binaries on the runner image, or pull from an **internal artifact mirror / Iron Bank tooling images**. Several of these tools are available as Iron Bank images.

## Vulnerability databases & rulesets (must be available offline)
- **Trivy:** host the vuln DB + Java DB in an internal OCI registry; set `db.repository` / `db.java-repository` in `policy/trivy/trivy.yaml` and pre-load before the scan (`trivy image --download-db-only`).
- **Grype:** host the Grype DB; set `GRYPE_DB_UPDATE_URL` to the internal listing.
- **OWASP Dependency-Check:** mirror the NVD data feed internally; configure `--connectionString`/`--dbDriverPath` to a local DB and `--nvdDatafeed`/`--cveUrlBase` to the mirror; pre-populate.
- **CodeQL:** use the CodeQL bundle distributed with GHES (the action resolves it from the GHES instance); no internet needed. **Semgrep:** vendor the registry rulesets you use (`p/security-audit`, etc.) into the repo or an internal location and reference them by path (the custom `policy/semgrep/dod-secure-coding.yml` already is).
- **OpenSSF Scorecard:** Scorecard reaches out to public APIs (GitHub, deps.dev, OSV) — on a fully air-gapped GHES, run a reduced check set against the GHES API only, or accept that this gate is degraded; document it.

## Signing & provenance (Sigstore alternatives)
- **`actions/attest-build-provenance`** uses GitHub's attestation API + the public Sigstore — on GHES it can use the GHES-hosted attestation store if available; otherwise generate SLSA provenance with `slsa-framework/slsa-github-generator` configured against your environment, or sign with **organization-managed keys backed by an HSM/KMS** instead of keyless.
- **`cosign`**: instead of keyless (public Fulcio/Rekor), use `cosign sign --key <kms-uri>` with your org's KMS/HSM key, and optionally a private Rekor/transparency log. Confirm the crypto is FIPS-validated (SC-13).
- The RPOC's admission control then verifies *your* signature/key — coordinate the trust root.

## Registry
- Use the enclave's container registry (Iron Bank / Repo One for base images; your platform's
  registry for app images) instead of GHCR. Update `env.REGISTRY`/`IMAGE_NAME` and the push/sign
  steps accordingly. The RPOC typically *provides* the container repo (RPOC requirement 12).

## STIG / SCAP content
- The `stig` gate ships a placeholder. In a DoD enclave you almost certainly already have the DISA
  SCAP benchmark content (the OS STIG, the Container Platform SRG, the Kubernetes STIG) — mount it
  on the runner and point `oscap xccdf eval` at it. Prefer an **Iron Bank** base image so the OS
  STIG is largely inherited (cite the image's hardening manifest + inherited-controls appendix).

## GitHub Pages dashboard
- GHES supports Pages; publish there. If Pages isn't enabled in your enclave, the dashboard `site/`
  is plain static files — host it on any internal static-web service, or rely on the GitHub-native
  views (the auto-maintained "ATO Status" issue + the `body-of-evidence` artifacts + GitHub
  Projects). The `ato-status-report.yml` workflow needs only `issues: write`.

## eMASS
- eMASS is reachable from the DoD network. The repo doesn't call eMASS; the `emass-package/` output
  is uploaded by a person. If you later add an eMASS REST API uploader workflow (DoD PKI client cert
  + `api-key` in Actions secrets), it must run on a runner with network access to the eMASS
  instance; treat the cert/key as the org's most sensitive secrets and gate the workflow on human
  approval.

## Edge / disconnected (RAISE)
- For production nodes that can't run ConMon (ships, subs, aircraft, tactical, air-gapped): run the
  full pipeline + ConMon against the **Staging/Pre-Prod** tier; the edge node syncs logs/updates
  with Staging as the mission allows. Document the sync mechanism and the handling of findings
  discovered while disconnected in `compliance/conmon/continuous-monitoring-strategy.md`.

## What stays the same
- The pipeline structure, the gate set, `policy/`, `scripts/`, the control catalog, the crosswalks,
  the eMASS package shape, and the dashboard — all unchanged. The deltas are entirely about *where
  the tools/DBs/actions/registry/signing-roots come from* and *where the runners live*.
