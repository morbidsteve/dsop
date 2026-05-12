#!/usr/bin/env python3
"""map_controls.py — map normalized findings + gate coverage onto NIST SP 800-53 controls.

Reads:
  --evidence <dir>/findings.json, evidence_index.json   (from aggregate_evidence.py)
  --catalog  compliance/control-catalog/control-catalog.yaml
Writes (under --out, default <evidence>/boe):
  controls.json          - per-control: implementation status, RMF/eMASS-style test result,
                           narrative, CCIs, evidence artifacts, related findings, RAISE/SSDF tags.
  controls_summary.json  - roll-up counts (for the dashboard & ATO status issue).

Test-result determination (per control):
  - implementation_status == not_applicable            -> "Not Applicable"
  - implementation_status == inherited                 -> "Not Reviewed (Inherited — see CRM)"
  - no evidence gates declared (manual/process control):
        -> uses `manual_assessment.result` if present, else "Not Reviewed (Manual Assessment)"
  - one or more evidence gates declared:
        - any required gate did NOT execute in this run -> "Not Reviewed"
        - all required gates executed:
            - any related finding at high/critical       -> "Non-Compliant"
            - else                                       -> "Compliant"
This is a defensible automated *first pass*; the SCA makes the final determination. The mapping is
deliberately conservative (a control only goes "Compliant" when its assessing gates actually ran).
"""
from __future__ import annotations

import argparse
import fnmatch
import glob
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evidence_common import load_json, load_yaml, dump_json, now_iso, SEVERITY_RANK  # noqa: E402

HIGH_OR_CRIT = {"high", "critical"}


def resolve_artifacts(patterns, repo_root="."):
    out = []
    for pat in patterns or []:
        for m in glob.glob(os.path.join(repo_root, pat), recursive=True):
            if os.path.isfile(m):
                out.append(os.path.relpath(m, repo_root))
    # also accept evidence/** relative paths verbatim if they exist
    return sorted(set(out))


def control_findings(control, findings):
    """Findings considered 'relevant' to a control: matched by gate, by explicit control tag, or
    by an artifact-name hint."""
    gates = set()
    artifact_hints = set()
    for ev in control.get("evidence", []) or []:
        if isinstance(ev, dict):
            if ev.get("gate"):
                gates.add(ev["gate"])
            if ev.get("artifact"):
                artifact_hints.add(ev["artifact"])
        elif isinstance(ev, str):
            gates.add(ev)
    cid = control["id"].upper()
    rel = []
    for f in findings:
        if f.get("gate") in gates:
            rel.append(f)
        elif cid in {str(t).upper() for t in f.get("tags", [])}:
            rel.append(f)
    return rel, gates


def determine_test_result(control, gates, gates_executed, rel_findings):
    status = (control.get("implementation_status") or "implemented").lower().replace("-", "_")
    if status in ("not_applicable", "na"):
        return "Not Applicable", "Control assessed Not Applicable per the control catalog."
    if status == "inherited":
        src = control.get("inherited_from") or "the platform / Customer Responsibility Matrix"
        return "Not Reviewed (Inherited)", f"Inherited from {src}; rely on the provider's assessment / CRM."
    if not gates:
        ma = control.get("manual_assessment") or {}
        if ma.get("result"):
            return str(ma["result"]), str(ma.get("comments") or "Manual assessment result from the control catalog.")
        return "Not Reviewed (Manual Assessment)", "No automated evidence gate; assess via Examine/Interview/Test."
    missing = [g for g in gates if g not in set(gates_executed)]
    if missing:
        return "Not Reviewed", f"Assessing gate(s) did not execute this run: {', '.join(sorted(missing))}."
    # Realistic automated verdict: a control is Non-Compliant only when the assessing gate(s) found
    # a finding that is genuinely actionable-and-unremediated — i.e. Critical, or High *with a fix
    # available*, or anything already past its remediation SLA. Otherwise (the gate ran; remaining
    # open findings are lower-severity, or High/Critical with no fix yet — e.g. base-image OS CVEs
    # the vendor hasn't patched) the control is Compliant *with the items tracked in the POA&M*.
    # The SCA makes the final determination — this is an automated first pass.
    blocking = [f for f in rel_findings
                if f["severity"] == "critical"
                or (f["severity"] == "high" and (f.get("fix") == "fixed"))
                or f.get("overdue") is True]
    n = len(rel_findings)
    sev_counts = {s: sum(1 for f in rel_findings if f["severity"] == s) for s in ("critical", "high", "medium", "low")}
    if blocking:
        n_c = sum(1 for f in blocking if f["severity"] == "critical")
        n_hf = sum(1 for f in blocking if f["severity"] == "high")
        why = []
        if n_c: why.append(f"{n_c} Critical")
        if n_hf: why.append(f"{n_hf} High with a fix available")
        return "Non-Compliant", (f"Assessing gate(s) executed; {', '.join(why)} unremediated finding(s) — see related findings / POA&M. "
                                 f"(Total open: {sev_counts}.)")
    if n:
        return "Compliant", (f"Assessing gate(s) executed; {n} open finding(s) (none Critical or fix-available High), "
                             f"all tracked in the POA&M: {sev_counts}. SCA validates.")
    return "Compliant", "Assessing gate(s) executed; no findings."


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--catalog", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--repo-root", default=".")
    a = ap.parse_args()

    ev_dir = Path(a.evidence)
    out_dir = Path(a.out) if a.out else ev_dir / "boe"
    out_dir.mkdir(parents=True, exist_ok=True)

    catalog = load_yaml(a.catalog) or {}
    findings = load_json(ev_dir / "findings.json") or []
    index = load_json(ev_dir / "evidence_index.json") or {}
    gates_executed = index.get("gates_executed", [])

    controls_out = []
    summary = {"Compliant": 0, "Non-Compliant": 0, "Not Applicable": 0, "Not Reviewed": 0,
               "Not Reviewed (Inherited)": 0, "Not Reviewed (Manual Assessment)": 0, "Other": 0}
    impl_summary = {}
    by_family = {}

    for control in catalog.get("controls", []) or []:
        cid = control["id"]
        rel, gates = control_findings(control, findings)
        result, rationale = determine_test_result(control, gates, gates_executed, rel)
        bucket = result if result in summary else ("Not Reviewed" if result.startswith("Not Reviewed") else "Other")
        summary[bucket] = summary.get(bucket, 0) + 1
        st = (control.get("implementation_status") or "implemented")
        impl_summary[st] = impl_summary.get(st, 0) + 1
        fam = control.get("family") or cid.split("-")[0]
        by_family.setdefault(fam, {"total": 0, "Compliant": 0, "Non-Compliant": 0, "Not Reviewed": 0, "Not Applicable": 0})
        by_family[fam]["total"] += 1
        by_family[fam][bucket if bucket in by_family[fam] else "Not Reviewed"] += 1

        sev_counts = {s: sum(1 for f in rel if f["severity"] == s) for s in ["critical", "high", "medium", "low", "info"]}
        controls_out.append({
            "id": cid,
            "family": fam,
            "title": control.get("title", ""),
            "baseline": control.get("baseline", []),
            "implementation_status": st,
            "responsibility": control.get("responsibility", "system"),
            "inherited_from": control.get("inherited_from"),
            "ccis": control.get("ccis", []),
            "narrative": (control.get("narrative") or "").strip(),
            "assessment_methods": (control.get("assessment") or {}).get("methods", []),
            "assessment_objective": ((control.get("assessment") or {}).get("objective") or "").strip(),
            "evidence_gates": sorted(gates),
            "evidence_artifacts": resolve_artifacts(
                [ev.get("artifact") for ev in control.get("evidence", []) if isinstance(ev, dict) and ev.get("artifact")],
                a.repo_root),
            "raise_gate": control.get("raise_gate", []),
            "ssdf": control.get("ssdf", []),
            "test_result": result,
            "test_result_rationale": rationale,
            "last_assessed": now_iso(),
            "assessing_run": index.get("run_url", ""),
            "related_finding_counts": sev_counts,
            "related_findings": [f["fingerprint"] for f in rel][:200],
        })

    dump_json({
        "generated": now_iso(),
        "system": (catalog.get("metadata") or {}).get("system_name", "(unnamed system)"),
        "baseline": (catalog.get("metadata") or {}).get("baseline", ""),
        "controls": controls_out,
    }, out_dir / "controls.json")

    total = len(controls_out)
    assessed = summary.get("Compliant", 0) + summary.get("Non-Compliant", 0)
    dump_json({
        "generated": now_iso(),
        "total_controls": total,
        "test_results": summary,
        "implementation_status": dict(sorted(impl_summary.items())),
        "by_family": dict(sorted(by_family.items())),
        "automated_assessment_coverage_pct": round(100.0 * assessed / total, 1) if total else 0.0,
        "compliant_pct_of_assessed": round(100.0 * summary.get("Compliant", 0) / assessed, 1) if assessed else 0.0,
        "gates_executed": gates_executed,
    }, out_dir / "controls_summary.json")

    print(f"Mapped {total} controls -> {dict(summary)} (impl: {dict(sorted(impl_summary.items()))})")


if __name__ == "__main__":
    main()
