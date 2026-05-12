#!/usr/bin/env python3
"""build_dashboard_data.py — produce site/data/*.json for the AO dashboard (and the ATO-status MD).

Default mode (build the dashboard data):
  reads  <evidence>/findings.json, evidence_index.json, boe/controls.json, boe/controls_summary.json,
         boe/poam.json, boe/conmon_history.json  and  the control catalog
  writes site/data/{meta,summary,controls,findings,poam,conmon,pipeline}.json

--status-issue-md mode:
  writes a Markdown summary (to --out) for the auto-maintained "ATO Status" issue.

The dashboard (site/index.html + assets/app.js) is a static single-page app that fetches these
JSON files; nothing else is needed to render it. Seed copies of these files are committed so the
site renders before the first pipeline run.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evidence_common import load_json, load_yaml, dump_json, now_iso  # noqa: E402

# Static description of the DevSecOps lifecycle gates this pipeline runs. (The control mapping is
# pulled live from the catalog so it stays in sync.)
GATES = [
    {"id": "build-test", "phase": "Build / Test", "name": "Build & unit test + coverage",
     "tools": ["pytest", "ruff"], "raise_gate": [], "fail_policy": "Tests must pass; coverage floor (configurable)."},
    {"id": "sast", "phase": "Test", "name": "Static Application Security Testing",
     "tools": ["CodeQL", "Semgrep (+ custom DoD rules)"], "raise_gate": [1],
     "fail_policy": "Build fails on new Critical/High; pre-existing -> POA&M."},
    {"id": "sca", "phase": "Build / Test", "name": "Software Composition Analysis (dependency vulns)",
     "tools": ["Trivy (fs)", "Grype", "OWASP Dependency-Check"], "raise_gate": [2],
     "fail_policy": "Build fails on Critical, or High with a fix available; else -> POA&M."},
    {"id": "sbom", "phase": "Build", "name": "Software Bill of Materials",
     "tools": ["Syft -> SPDX 2.3 + CycloneDX 1.5 (source & image)"], "raise_gate": [2],
     "fail_policy": "Always produced; structurally checked vs NTIA minimum elements."},
    {"id": "license", "phase": "Build", "name": "OSS license / component policy",
     "tools": ["license policy check (vs policy/allowed-licenses.yaml)"], "raise_gate": [2],
     "fail_policy": "Build fails on a disallowed license; review-required -> POA&M."},
    {"id": "secrets", "phase": "Develop / Build", "name": "Secrets detection",
     "tools": ["Gitleaks", "TruffleHog", "GitHub push protection"], "raise_gate": [3],
     "fail_policy": "Any verified/high-confidence secret = hard fail."},
    {"id": "iac", "phase": "Build", "name": "IaC / configuration scanning",
     "tools": ["Checkov", "KICS", "Trivy config", "kube-linter", "Conftest/OPA"], "raise_gate": [],
     "fail_policy": "Build fails on Critical/High or any Rego deny; else -> POA&M. (RAISE: expected practice, not a named gate.)"},
    {"id": "container", "phase": "Build", "name": "Container image scan + hardening + sign + provenance",
     "tools": ["Trivy (image)", "Grype", "Hadolint", "Dockle", "Syft (image SBOM)", "cosign/Sigstore", "SLSA provenance"],
     "raise_gate": [4, 7, 8], "fail_policy": "Build fails on Critical image CVE, High-with-fix, or FATAL hardening; non-root + healthcheck required; signed image pushed to GHCR."},
    {"id": "dast", "phase": "Test", "name": "Dynamic Application Security Testing",
     "tools": ["OWASP ZAP baseline"], "raise_gate": [5], "fail_policy": "Build fails on ZAP High; Medium/Low -> POA&M."},
    {"id": "stig", "phase": "Test / Operate", "name": "STIG / SCAP compliance",
     "tools": ["OpenSCAP", "(supply your DISA STIG/SRG SCAP content)"], "raise_gate": [],
     "fail_policy": "Build fails on open CAT I; CAT II/III -> POA&M. (DISA Container Platform SRG / Kubernetes STIG.)"},
    {"id": "supply-chain", "phase": "Monitor", "name": "Supply-chain hygiene",
     "tools": ["OpenSSF Scorecard"], "raise_gate": [], "fail_policy": "Reported; weak checks -> findings/POA&M candidates."},
    {"id": "review", "phase": "Release", "name": "ISSM review checkpoint",
     "tools": ["PR review (CODEOWNERS) + ATO Status issue + dashboard"], "raise_gate": [6],
     "fail_policy": "Branch protection requires Code Owner review; release gated on the BoE being current."},
    {"id": "body-of-evidence", "phase": "Release / Monitor", "name": "Body-of-Evidence assembly",
     "tools": ["aggregate_evidence", "map_controls", "generate_poam", "update_conmon", "build_emass_package", "build_dashboard_data"],
     "raise_gate": [], "fail_policy": "Always runs; produces controls/POA&M/ConMon/eMASS package/dashboard."},
]


def _trim_finding(f):
    return {k: f.get(k) for k in ("fingerprint", "gate", "tool", "severity", "title", "location",
                                  "component", "version", "cve", "cwe", "fix", "rule_id", "tags", "run_url")}


def _trim_control(c):
    return {k: c.get(k) for k in ("id", "family", "title", "implementation_status", "responsibility",
                                  "inherited_from", "ccis", "test_result", "test_result_rationale",
                                  "narrative", "evidence_gates", "evidence_artifacts", "raise_gate",
                                  "ssdf", "related_finding_counts", "last_assessed", "assessing_run")}


def build_data(args):
    ev = Path(args.evidence)
    site = Path(args.site)
    data = site / "data"
    data.mkdir(parents=True, exist_ok=True)

    catalog = load_yaml(args.catalog) if args.catalog else {}
    meta_cat = (catalog or {}).get("metadata", {}) if catalog else {}
    findings = load_json(ev / "findings.json") or []
    index = load_json(ev / "evidence_index.json") or {}
    controls_doc = load_json(ev / "boe" / "controls.json") or {"controls": []}
    controls = controls_doc.get("controls", [])
    csum = load_json(ev / "boe" / "controls_summary.json") or {}
    poam = load_json(ev / "boe" / "poam.json") or {}
    conmon = load_json(ev / "boe" / "conmon_history.json") or {"snapshots": []}

    scorecard_overall = None
    for f in findings:
        if f.get("tool") == "openssf-scorecard" and "overall score" in (f.get("title") or "").lower():
            import re
            m = re.search(r"(\d+(?:\.\d+)?)/10", f["title"])
            if m:
                scorecard_overall = float(m.group(1))

    # meta.json
    dump_json({
        "generated": now_iso(),
        "system_name": meta_cat.get("system_name", "(unnamed system)"),
        "system_acronym": meta_cat.get("system_acronym", ""),
        "categorization": meta_cat.get("categorization", ""),
        "baseline": meta_cat.get("baseline", controls_doc.get("baseline", "")),
        "authorization_status": meta_cat.get("authorization_status", "(not yet authorized — see ATO milestones)"),
        "authorization_type": meta_cat.get("authorization_type", "(ATO / cATO / RAISE incorporation — TBD)"),
        "rpoc": meta_cat.get("raise_rpoc", ""),
        "emass_system_id": meta_cat.get("emass_system_id", ""),
        "repo": args.repo, "ref": args.ref, "sha": args.sha, "run_url": args.run_url or index.get("run_url", ""),
        "scorecard_overall": scorecard_overall,
    }, data / "meta.json")

    # summary.json
    tr = csum.get("test_results", {})
    dump_json({
        "generated": now_iso(),
        "controls": {
            "total": csum.get("total_controls", len(controls)),
            "results": tr,
            "compliant": tr.get("Compliant", 0),
            "noncompliant": tr.get("Non-Compliant", 0),
            "not_reviewed": sum(v for k, v in tr.items() if k.startswith("Not Reviewed")),
            "not_applicable": tr.get("Not Applicable", 0),
            "by_family": csum.get("by_family", {}),
            "implementation_status": csum.get("implementation_status", {}),
            "automated_assessment_coverage_pct": csum.get("automated_assessment_coverage_pct", 0.0),
            "compliant_pct_of_assessed": csum.get("compliant_pct_of_assessed", 0.0),
        },
        "findings": {
            "total": index.get("total_findings", len(findings)),
            "by_severity": index.get("by_severity", {}),
            "by_gate": index.get("by_gate", {}),
            "by_tool": index.get("by_tool", {}),
        },
        "poam": {
            "open": poam.get("total_items", 0), "overdue": poam.get("overdue", 0),
            "out_of_raise_scope": poam.get("out_of_raise_scope", 0), "by_cat": poam.get("by_cat", {}),
        },
        "gates_executed": index.get("gates_executed", []),
        "sbom_component_count": index.get("sbom_component_count", 0),
        "scorecard_overall": scorecard_overall,
        "raise_gates_status": _raise_gate_status(index.get("gates_executed", [])),
    }, data / "summary.json")

    dump_json({"generated": now_iso(), "controls": [_trim_control(c) for c in controls]}, data / "controls.json")
    dump_json({"generated": now_iso(), "count": len(findings), "findings": [_trim_finding(f) for f in findings]}, data / "findings.json")
    dump_json({"generated": now_iso(), "policy": poam.get("policy", {}), "count": poam.get("total_items", 0),
               "items": poam.get("items", [])}, data / "poam.json")
    # conmon trend — drop the heavy fingerprint sets for the UI
    snaps = [{k: v for k, v in s.items() if k != "finding_fingerprints"} for s in conmon.get("snapshots", [])]
    dump_json({"generated": now_iso(), "snapshots": snaps}, data / "conmon.json")
    # pipeline.json — gate list + which controls each gate evidences (live from the catalog)
    gate_to_controls = {}
    for c in controls:
        for g in c.get("evidence_gates", []) or []:
            gate_to_controls.setdefault(g, []).append(c["id"])
    pipe = []
    for g in GATES:
        gg = dict(g)
        gg["controls_evidenced"] = sorted(set(gate_to_controls.get(g["id"], [])))
        gg["executed"] = g["id"] in index.get("gates_executed", []) or g["id"] in ("review", "body-of-evidence")
        gg["finding_count"] = sum(1 for f in findings if f.get("gate") == g["id"])
        pipe.append(gg)
    dump_json({"generated": now_iso(), "gates": pipe}, data / "pipeline.json")

    print(f"Dashboard data written to {data} — {len(controls)} controls, {len(findings)} findings, "
          f"{poam.get('total_items', 0)} POA&M, {len(snaps)} ConMon snapshots.")


def _raise_gate_status(gates_executed):
    g = set(gates_executed)
    return [
        {"gate": 1, "name": "SAST (custom source code)", "satisfied_by": "sast", "executed": "sast" in g},
        {"gate": 2, "name": "Dependency list / SBOM", "satisfied_by": "sbom + sca + license", "executed": ("sbom" in g or "sca" in g)},
        {"gate": 3, "name": "Secrets / keys detection", "satisfied_by": "secrets", "executed": "secrets" in g},
        {"gate": 4, "name": "Container security scanning", "satisfied_by": "container", "executed": "container" in g},
        {"gate": 5, "name": "DAST", "satisfied_by": "dast", "executed": "dast" in g},
        {"gate": 6, "name": "RPOC ISSM review step", "satisfied_by": "review (CODEOWNERS + ATO Status issue + dashboard)", "executed": True},
        {"gate": 7, "name": "Sign the release container image", "satisfied_by": "container (cosign/Sigstore + SLSA provenance)", "executed": "container" in g},
        {"gate": 8, "name": "Store the release image in an artifact repository", "satisfied_by": "container (push to GHCR)", "executed": "container" in g},
    ]


def status_issue_md(args):
    site = Path(args.site)
    data = site / "data"
    meta = load_json(data / "meta.json") or {}
    summary = load_json(data / "summary.json") or {}
    poam = load_json(data / "poam.json") or {"items": []}
    conmon = load_json(data / "conmon.json") or {"snapshots": []}
    c = summary.get("controls", {}); fnd = summary.get("findings", {}); pm = summary.get("poam", {})
    last_snap = conmon["snapshots"][-1] if conmon.get("snapshots") else {}

    L = []
    L.append(f"<!-- auto-maintained by .github/workflows/ato-status-report.yml — do not edit by hand -->")
    L.append(f"## ATO / cATO Status — {meta.get('system_name','(system)')} {('('+meta.get('system_acronym','')+')') if meta.get('system_acronym') else ''}")
    L.append("")
    L.append(f"_Last refreshed: {now_iso()}._  ·  Authorization: **{meta.get('authorization_status','(TBD)')}** ({meta.get('authorization_type','')})")
    L.append("")
    L.append(f"🔗 **AO dashboard:** {('https://'+meta['repo'].split('/')[0]+'.github.io/'+meta['repo'].split('/')[-1]+'/') if meta.get('repo') and '/' in meta.get('repo','') else '(GitHub Pages — enable Pages with source = GitHub Actions)'}")
    if meta.get("run_url"):
        L.append(f"🔗 **Assessing pipeline run:** {meta['run_url']}")
    L.append("")
    L.append("### Controls")
    L.append(f"- **{c.get('compliant',0)} Compliant** · **{c.get('noncompliant',0)} Non-Compliant** · {c.get('not_reviewed',0)} Not Reviewed · {c.get('not_applicable',0)} Not Applicable  (of {c.get('total',0)})")
    L.append(f"- Automated assessment coverage: **{c.get('automated_assessment_coverage_pct',0)}%**; compliant-of-assessed: {c.get('compliant_pct_of_assessed',0)}%")
    L.append("")
    L.append("### Findings (open, all gates)")
    bs = fnd.get("by_severity", {})
    L.append(f"- 🔴 Critical: **{bs.get('critical',0)}** · 🟠 High: **{bs.get('high',0)}** · 🟡 Medium: {bs.get('medium',0)} · 🔵 Low: {bs.get('low',0)} · ℹ️ Info: {bs.get('info',0)}")
    L.append(f"- Pipeline gates executed: {', '.join(summary.get('gates_executed',[])) or '(none recorded)'}")
    if summary.get("scorecard_overall") is not None:
        L.append(f"- OpenSSF Scorecard (repo hygiene): {summary['scorecard_overall']}/10")
    L.append("")
    L.append("### POA&M")
    L.append(f"- **{pm.get('open',0)} open** items — {pm.get('overdue',0)} overdue, {pm.get('out_of_raise_scope',0)} out-of-RAISE-scope.  By CAT: {pm.get('by_cat',{})}")
    overdue_items = [i for i in poam.get("items", []) if i.get("overdue")][:10]
    if overdue_items:
        L.append("")
        L.append("**Overdue POA&M items (top 10):**")
        for i in overdue_items:
            L.append(f"  - `{i.get('severity_value')}` {i.get('control_vulnerability_description','')[:120].splitlines()[0]} — due {i.get('scheduled_completion_date')} ({i.get('source_identifying_control_vulnerability','')})")
    L.append("")
    L.append("### RAISE 2.0 Security Gates")
    for g in summary.get("raise_gates_status", []):
        L.append(f"- Gate {g['gate']} — {g['name']}: {'✅ executed' if g['executed'] else '⚠️ not executed this run'}  _(via {g['satisfied_by']})_")
    L.append("")
    L.append("### Continuous-monitoring trend (recent)")
    if conmon.get("snapshots"):
        L.append("| Date | Findings (C/H/M/L) | Controls C/NC | POA&M open (overdue) |")
        L.append("|---|---|---|---|")
        for s in conmon["snapshots"][-8:]:
            sb = s.get("findings_by_severity", {})
            cr = s.get("controls_results", {})
            L.append(f"| {s.get('date')} | {sb.get('critical',0)}/{sb.get('high',0)}/{sb.get('medium',0)}/{sb.get('low',0)} | {cr.get('Compliant',0)}/{cr.get('Non-Compliant',0)} | {s.get('poam_open',0)} ({s.get('poam_overdue',0)}) |")
    else:
        L.append("_(no snapshots yet — run the pipeline)_")
    L.append("")
    L.append("---")
    L.append("- 📦 The eMASS submission package is published as a GitHub **Release** asset on each version tag (`emass-package.zip`), and as a workflow artifact (`body-of-evidence` / `emass-package`) on every run.")
    L.append("- 📖 See `docs/ao-quickstart.md` for how to read this, and `compliance/crosswalks/` for the RMF / cATO / RAISE 2.0 / SSDF / eMASS mappings.")
    L.append("- ⚠️ Test results are an automated first pass; the SCA makes the final determination and signs the SAR. Confirm all mappings against the controlling documents (`compliance/references.md`).")
    Path(args.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"Wrote ATO status markdown -> {args.out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence", default="evidence")
    ap.add_argument("--catalog", default="compliance/control-catalog/control-catalog.yaml")
    ap.add_argument("--site", default="site")
    ap.add_argument("--repo", default="")
    ap.add_argument("--ref", default="")
    ap.add_argument("--sha", default="")
    ap.add_argument("--run-url", default="")
    ap.add_argument("--status-issue-md", action="store_true")
    ap.add_argument("--out", default="ato-status.md")
    a = ap.parse_args()
    if a.status_issue_md:
        status_issue_md(a)
    else:
        build_data(a)


if __name__ == "__main__":
    main()
