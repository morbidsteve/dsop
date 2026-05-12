<!-- Change-control record. RMF/SSDF evidence: CM-3 (configuration change control),
     CM-4 (security impact analysis), SA-10 (developer CM), SSDF PW.2 (design review). -->

## What & why
<!-- Summary of the change and the driver (requirement / finding / POA&M item / CVE). -->

Closes #

## Type of change
- [ ] Feature / capability
- [ ] Bug fix
- [ ] Security fix / vulnerability remediation (link the finding / GHSA / POA&M item)
- [ ] Dependency / base-image update
- [ ] Infrastructure-as-code change
- [ ] Pipeline / tooling / policy change
- [ ] Compliance content (control catalog, SSP, crosswalks, ConMon)
- [ ] Documentation only

## Security impact analysis (CM-4)
- [ ] No change to the authorization boundary, data flows, ports/protocols/services, or trust relationships.
- [ ] Change to boundary / data flow / PPS / trust relationship — described below, SSP & PPSM updated, ISSM/SCA notified.
- [ ] New or changed external interface / dependency / privilege — described below.
- [ ] Affects controls: <!-- list NIST 800-53 control IDs, or "none assessed to be affected" -->

Notes:

## Verification
- [ ] Unit tests added/updated and passing.
- [ ] `devsecops-pipeline` checks pass (SAST, SCA, SBOM, secrets, IaC, container scan, DAST, STIG/SCAP, license).
- [ ] No new Critical/High findings introduced (or: documented in the POA&M with a remediation date — link below).
- [ ] CHANGELOG.md updated (RAISE App-Owner artifact / SA-10 release record).
- [ ] For container changes: image still builds non-root, minimal, with healthcheck; image scan clean per `policy/thresholds.yaml`.

## Reviewer checklist (Code Owner)
- [ ] Change is within approved scope; no unauthorized expansion of functionality (CM-7).
- [ ] Separation of duties respected (author ≠ sole approver) (CM-5).
- [ ] Compliance content changes reviewed by RMF team where applicable.
