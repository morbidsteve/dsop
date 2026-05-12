#!/usr/bin/env python3
"""build_emass_package.py — assemble the eMASS-ready submission package from the Body of Evidence.

Reads:
  --evidence <dir>   (findings.json, evidence_index.json, sbom/, boe/controls.json, boe/poam.*)
  --catalog  compliance/control-catalog/control-catalog.yaml
  --ssp      compliance/ssp/system-security-plan.md
Writes (under --out, default <evidence>/emass-package):
  MANIFEST.json                  - machine index of every file + which control(s)/CCI(s) & eMASS artifact category it supports
  ato-package-summary.md         - human-readable index + submission instructions + posture snapshot
  controls.json / controls.csv   - per-control implementation status + narrative + responsibility + CCIs
  test-results.csv               - control test results (Compliant / Non-Compliant / NA / Not Reviewed) with rationale + assessing run
  poam.csv                       - the POA&M (copied from boe/poam.csv; eMASS column layout)
  hardware-software-list.csv     - software baseline derived from the merged SBOM (HW rows left as a template)
  ppsm.csv                       - Ports/Protocols/Services template (populate from the SSP)
  system-security-plan.md        - copy of the SSP
  artifacts/                     - the actual scan reports / SBOMs / attestations, organized by gate

IMPORTANT: column names below mirror the well-documented eMASS field set, but the EXACT import
template (column order, required flags) is defined in the CAC-protected eMASS User Guide for your
eMASS instance — confirm before importing. See compliance/crosswalks/emass-crosswalk.md.
"""
from __future__ import annotations

import argparse
import csv
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evidence_common import load_json, load_yaml, dump_json, now_iso  # noqa: E402

# eMASS "Artifact" category/type hints, by gate. (eMASS lets you tag each uploaded artifact with a
# category and type; these are sensible defaults — adjust to your eMASS instance's value lists.)
ARTIFACT_META = {
    "sast":         {"category": "Test Results", "type": "Static Application Security Testing (SAST) report"},
    "sca":          {"category": "Test Results", "type": "Software Composition Analysis / dependency vulnerability report"},
    "container":    {"category": "Test Results", "type": "Container image vulnerability scan + hardening report"},
    "iac":          {"category": "Test Results", "type": "Infrastructure-as-Code / configuration scan report"},
    "secrets":      {"category": "Test Results", "type": "Secrets detection scan report"},
    "dast":         {"category": "Test Results", "type": "Dynamic Application Security Testing (DAST) report"},
    "stig":         {"category": "Test Results", "type": "STIG/SCAP compliance results (.ckl / OpenSCAP)"},
    "license":      {"category": "Other",        "type": "Open-source license compliance report"},
    "supply-chain": {"category": "Other",        "type": "Supply-chain hygiene (OpenSSF Scorecard) report"},
    "sbom":         {"category": "System",       "type": "Software Bill of Materials (SPDX / CycloneDX)"},
    "provenance":   {"category": "Other",        "type": "Build provenance / image signature attestation (SLSA / Sigstore)"},
}

# Which evidence subdirectories (relative to <evidence>) get bundled into artifacts/<gate>/
EVIDENCE_GATE_DIRS = {
    "sast": ["sast"], "sca": ["sca"], "container": ["container"], "iac": ["iac"],
    "secrets": ["secrets"], "dast": ["dast"], "stig": ["stig"], "license": ["license"],
    "supply-chain": ["scorecard"], "sbom": ["sbom"], "provenance": ["provenance"],
}

CONTROLS_CSV_COLS = ["Control Acronym", "Control Title", "Family", "Baseline",
                     "Implementation Status", "Responsibility (Common/System/Hybrid/Inherited)",
                     "Inherited From", "CCIs", "Implementation Narrative / Control Implementation",
                     "RAISE 2.0 Security Gate(s)", "SSDF Practice(s)"]
TESTRESULTS_CSV_COLS = ["Control Acronym", "Assessment Procedure(s) / Method(s)", "Test Result",
                        "Test Result Rationale", "Related Open High/Critical Findings", "Assessed (UTC)",
                        "Assessing Pipeline Run"]
HWSW_CSV_COLS = ["Asset Type (HW/SW)", "Component Name", "Version", "Vendor/Supplier", "PURL / Identifier",
                 "License(s)", "Function/Notes", "In Authorization Boundary (Y/N)", "STIG/SRG Applicable"]
PPSM_CSV_COLS = ["Port", "Protocol", "Service", "Direction (Inbound/Outbound)", "Purpose / Description",
                 "Boundary (Internal/Boundary/External)", "Data Classification", "PPSM CAL Category Assurance Level",
                 "Source/Destination", "Justification"]


def safe_copytree(src: Path, dst: Path):
    if not src.exists():
        return 0
    n = 0
    for p in src.rglob("*"):
        if p.is_file():
            rel = p.relative_to(src)
            target = dst / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(p, target)
                n += 1
            except Exception:
                pass
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--catalog", required=True)
    ap.add_argument("--ssp", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--release", default="")
    a = ap.parse_args()

    ev = Path(a.evidence)
    out = Path(a.out) if a.out else ev / "emass-package"
    if out.exists():
        shutil.rmtree(out, ignore_errors=True)
    (out / "artifacts").mkdir(parents=True, exist_ok=True)

    catalog = load_yaml(a.catalog) or {}
    meta = catalog.get("metadata") or {}
    controls_doc = load_json(ev / "boe" / "controls.json") or {"controls": []}
    controls = controls_doc.get("controls", [])
    controls_summary = load_json(ev / "boe" / "controls_summary.json") or {}
    poam = load_json(ev / "boe" / "poam.json") or {}
    index = load_json(ev / "evidence_index.json") or {}
    components_doc = load_json(ev / "sbom" / "components.json") or {"components": []}

    # ---- copy SSP ----
    ssp_dst = out / "system-security-plan.md"
    try:
        shutil.copy2(a.ssp, ssp_dst)
    except Exception:
        ssp_dst.write_text("# System Security Plan\n\n(See compliance/ssp/system-security-plan.md in the repo.)\n", encoding="utf-8")

    # ---- controls.json / controls.csv ----
    dump_json({"generated": now_iso(), "system": controls_doc.get("system"), "baseline": controls_doc.get("baseline"),
               "controls": controls}, out / "controls.json")
    with open(out / "controls.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(CONTROLS_CSV_COLS)
        for c in controls:
            w.writerow([c["id"], c.get("title", ""), c.get("family", ""), ";".join(c.get("baseline", [])),
                        c.get("implementation_status", ""), c.get("responsibility", ""), c.get("inherited_from") or "",
                        ";".join(c.get("ccis", [])), (c.get("narrative") or "").replace("\n", " ").strip(),
                        ";".join(str(x) for x in c.get("raise_gate", [])), ";".join(c.get("ssdf", []))])

    # ---- test-results.csv ----
    with open(out / "test-results.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(TESTRESULTS_CSV_COLS)
        for c in controls:
            fc = c.get("related_finding_counts", {}) or {}
            hc = (fc.get("high", 0) + fc.get("critical", 0))
            w.writerow([c["id"], ";".join(c.get("assessment_methods", [])) or "Examine; Test",
                        c.get("test_result", ""), (c.get("test_result_rationale") or "").replace("\n", " "),
                        hc, c.get("last_assessed", ""), c.get("assessing_run", "")])

    # ---- poam.csv (copy) ----
    src_poam = ev / "boe" / "poam.csv"
    if src_poam.exists():
        shutil.copy2(src_poam, out / "poam.csv")
    else:
        (out / "poam.csv").write_text("(no POA&M generated — run generate_poam.py)\n", encoding="utf-8")

    # ---- hardware-software-list.csv ----
    with open(out / "hardware-software-list.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(HWSW_CSV_COLS)
        w.writerow(["# Hardware rows: populate from the SSP / hosting platform inventory (the platform / RPOC typically", "", "", "", "", "", "", "", ""])
        w.writerow(["#   provides the HW baseline as inherited/common). Software rows below are derived from the SBOM.", "", "", "", "", "", "", "", ""])
        for c in components_doc.get("components", []):
            lic = ";".join(x for x in (c.get("licenses") or []) if x)
            w.writerow(["SW", c.get("name", ""), c.get("version", ""), "", c.get("purl") or "", lic,
                        c.get("type", "library"), "Y", "If applicable"])

    # ---- ppsm.csv (template) ----
    with open(out / "ppsm.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(PPSM_CSV_COLS)
        w.writerow(["443", "TCP/HTTPS (TLS 1.2+)", "Application API (sample-app)", "Inbound",
                    "HTTPS access to the application API", "Boundary", "(per categorization)",
                    "(per DoD PPSM CAL)", "Authorized clients", "Primary service interface — registered in PPSM"])
        w.writerow(["# Populate this from the SSP / your PPSM registration; one row per port/protocol/service.", "", "", "", "", "", "", "", "", ""])

    # ---- bundle artifacts ----
    artifact_manifest = []
    for gate, subdirs in EVIDENCE_GATE_DIRS.items():
        for sd in subdirs:
            src = ev / sd
            n = safe_copytree(src, out / "artifacts" / gate)
            if n:
                mm = ARTIFACT_META.get(gate, {"category": "Test Results", "type": gate})
                # which controls reference this gate?
                related = [c["id"] for c in controls if gate in (c.get("evidence_gates") or [])]
                ccis = sorted({cci for c in controls if gate in (c.get("evidence_gates") or []) for cci in c.get("ccis", [])})
                for p in sorted((out / "artifacts" / gate).rglob("*")):
                    if p.is_file():
                        artifact_manifest.append({
                            "path": str(p.relative_to(out)),
                            "gate": gate,
                            "emass_artifact_category": mm["category"],
                            "emass_artifact_type": mm["type"],
                            "supports_controls": related,
                            "supports_ccis": ccis,
                        })
    # raw normalized evidence too
    for f in ["findings.json", "evidence_index.json"]:
        if (ev / f).exists():
            shutil.copy2(ev / f, out / "artifacts" / f)
            artifact_manifest.append({"path": f"artifacts/{f}", "gate": "all",
                                      "emass_artifact_category": "Test Results",
                                      "emass_artifact_type": "Consolidated normalized findings / evidence index",
                                      "supports_controls": ["CA-2", "CA-7", "RA-5"], "supports_ccis": []})
    for f in ["controls.json", "controls_summary.json", "poam.json"]:
        if (ev / "boe" / f).exists():
            shutil.copy2(ev / "boe" / f, out / "artifacts" / f)
    if (ev / "boe" / "conmon_history.json").exists():
        shutil.copy2(ev / "boe" / "conmon_history.json", out / "artifacts" / "conmon_history.json")
        artifact_manifest.append({"path": "artifacts/conmon_history.json", "gate": "conmon",
                                  "emass_artifact_category": "Continuous Monitoring",
                                  "emass_artifact_type": "Continuous monitoring history / trend",
                                  "supports_controls": ["CA-7"], "supports_ccis": []})

    # ---- MANIFEST.json ----
    tr = controls_summary.get("test_results", {})
    manifest = {
        "generated": now_iso(),
        "package_type": "DoD RMF / RAISE 2.0 Authorization Body of Evidence (auto-assembled by the DSOP pipeline)",
        "release": a.release or "(unreleased / working)",
        "system": {
            "name": meta.get("system_name", "(unnamed system)"),
            "acronym": meta.get("system_acronym", ""),
            "categorization": meta.get("categorization", ""),
            "baseline": meta.get("baseline", ""),
            "emass_system_id": meta.get("emass_system_id", "(TBD)"),
            "ditpr_don_id": meta.get("ditpr_don_id", "(TBD)"),
            "dadms_id": meta.get("dadms_id", "(TBD)"),
            "authorization_boundary": meta.get("authorization_boundary_summary", ""),
            "rpoc": meta.get("raise_rpoc", "(TBD — the RAISE Platform of Choice this app is incorporated into, if applicable)"),
        },
        "posture": {
            "controls_total": controls_summary.get("total_controls", 0),
            "controls_compliant": tr.get("Compliant", 0),
            "controls_noncompliant": tr.get("Non-Compliant", 0),
            "controls_not_reviewed": sum(v for k, v in tr.items() if k.startswith("Not Reviewed")),
            "controls_not_applicable": tr.get("Not Applicable", 0),
            "automated_assessment_coverage_pct": controls_summary.get("automated_assessment_coverage_pct", 0.0),
            "poam_open": poam.get("total_items", 0),
            "poam_overdue": poam.get("overdue", 0),
            "poam_out_of_raise_scope": poam.get("out_of_raise_scope", 0),
            "poam_by_cat": poam.get("by_cat", {}),
            "findings_by_severity": index.get("by_severity", {}),
            "gates_executed": index.get("gates_executed", []),
            "sbom_component_count": index.get("sbom_component_count", 0),
            "assessing_run": index.get("run_url", ""),
        },
        "files": {
            "system_security_plan": "system-security-plan.md",
            "controls": ["controls.json", "controls.csv"],
            "test_results": ["test-results.csv"],
            "poam": ["poam.csv"],
            "hardware_software_baseline": ["hardware-software-list.csv"],
            "ppsm": ["ppsm.csv"],
            "artifacts_index": [a["path"] for a in artifact_manifest],
        },
        "artifacts": artifact_manifest,
        "important_notes": [
            "Confirm the eMASS POA&M import template columns/order against your eMASS instance's User Guide before importing (compliance/crosswalks/emass-crosswalk.md).",
            "Hardware baseline rows and PPSM rows are templates — populate from the SSP / hosting platform inventory.",
            "Test results here are an automated first pass; the Security Control Assessor (SCA) makes the final determination and signs the SAR.",
            "Inherited/common controls rely on the platform/RPOC assessment and the Customer Responsibility Matrix — see compliance/templates/customer-responsibility-matrix.md.",
        ],
    }
    dump_json(manifest, out / "MANIFEST.json")

    # ---- ato-package-summary.md ----
    sysm = manifest["system"]; pos = manifest["posture"]
    lines = []
    lines.append(f"# ATO / RAISE 2.0 Submission Package — {sysm['name']} {('('+sysm['acronym']+')') if sysm['acronym'] else ''}")
    lines.append("")
    lines.append(f"_Auto-assembled by the DSOP DevSecOps pipeline on {now_iso()}. Release: {manifest['release']}._")
    lines.append("")
    lines.append("> This package is the **Body of Evidence** for the system's RMF authorization, formatted for upload into eMASS. "
                 "It is generated from the pipeline's security gates; the **SCA** validates the test results and signs the SAR, "
                 "and the **AO** (and, for cATO, the DoD CISO; for RAISE, the RPOC ISSM/AO) renders the authorization decision.")
    lines.append("")
    lines.append("## System")
    for k, v in [("Name", sysm["name"]), ("Acronym", sysm["acronym"]), ("Categorization (C-I-A)", sysm["categorization"]),
                 ("Control baseline", sysm["baseline"]), ("eMASS System ID", sysm["emass_system_id"]),
                 ("DITPR-DON ID", sysm["ditpr_don_id"]), ("DADMS ID", sysm["dadms_id"]),
                 ("Authorization boundary", sysm["authorization_boundary"]), ("RAISE Platform of Choice (RPOC)", sysm["rpoc"])]:
        lines.append(f"- **{k}:** {v or '(TBD)'}")
    lines.append("")
    lines.append("## Posture snapshot")
    lines.append(f"- Controls: **{pos['controls_compliant']} Compliant**, **{pos['controls_noncompliant']} Non-Compliant**, "
                 f"{pos['controls_not_reviewed']} Not Reviewed, {pos['controls_not_applicable']} Not Applicable "
                 f"(of {pos['controls_total']}; automated assessment coverage {pos['automated_assessment_coverage_pct']}%).")
    lines.append(f"- POA&M: **{pos['poam_open']} open** ({pos['poam_overdue']} overdue, {pos['poam_out_of_raise_scope']} out-of-RAISE-scope); "
                 f"by CAT: {pos['poam_by_cat']}.")
    lines.append(f"- Findings by severity: {pos['findings_by_severity']}.")
    lines.append(f"- Pipeline gates executed: {', '.join(pos['gates_executed']) or '(none recorded)'}.")
    lines.append(f"- SBOM components: {pos['sbom_component_count']}. Assessing run: {pos['assessing_run'] or '(n/a)'}.")
    lines.append("")
    lines.append("## Contents")
    lines.append("| File | Purpose | eMASS destination |")
    lines.append("|---|---|---|")
    lines.append("| `system-security-plan.md` | System Security Plan | System details / control implementation; upload as an Artifact |")
    lines.append("| `controls.json` / `controls.csv` | Per-control implementation status, responsibility, CCIs, narrative | Security Controls (implementation details) |")
    lines.append("| `test-results.csv` | Control test results + rationale + assessing run | Security Controls > Test Results |")
    lines.append("| `poam.csv` | POA&M in eMASS column layout | POA&M (bulk import — confirm template) |")
    lines.append("| `hardware-software-list.csv` | SW baseline from the SBOM (+ HW template) | Hardware/Software baseline |")
    lines.append("| `ppsm.csv` | Ports/Protocols/Services template | PPSM |")
    lines.append("| `artifacts/<gate>/...` | Raw scan reports, SBOMs, attestations | Artifacts (tagged per `MANIFEST.json`) |")
    lines.append("| `MANIFEST.json` | Machine index: every file → control(s)/CCI(s) → eMASS artifact category | (reference) |")
    lines.append("")
    lines.append("## Submission steps")
    lines.append("See **`docs/emass-submission-runbook.md`** in the repo for the detailed runbook. In brief:")
    lines.append("1. Verify the system record in eMASS matches `MANIFEST.json > system` (categorization, baseline, IDs, boundary).")
    lines.append("2. Update control **implementation status & narrative** from `controls.csv` (or via the eMASS API using the same data).")
    lines.append("3. Enter **test results** from `test-results.csv`; attach the relevant `artifacts/<gate>/...` files to each control per `MANIFEST.json > artifacts`.")
    lines.append("4. Import the **POA&M** from `poam.csv` (verify column mapping against your eMASS POA&M import template first).")
    lines.append("5. Update the **Hardware/Software baseline** and **PPSM** from the CSVs.")
    lines.append("6. Initiate the **Control Approval Chain / Package Approval Chain** workflow for SCA → AO review.")
    lines.append("")
    lines.append("## Caveats")
    for note in manifest["important_notes"]:
        lines.append(f"- {note}")
    (out / "ato-package-summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"eMASS package assembled at {out} — {len(artifact_manifest)} artifact file(s), "
          f"{len(controls)} controls, {poam.get('total_items', 0)} POA&M item(s).")


if __name__ == "__main__":
    main()
