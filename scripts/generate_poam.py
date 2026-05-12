#!/usr/bin/env python3
"""generate_poam.py — turn open findings (above threshold) into POA&M rows in the eMASS layout.

Reads:
  --evidence <dir>/findings.json (+ boe/controls.json for control linkage)
  --thresholds policy/thresholds.yaml   (poam.min_severity, poam.sla_days, severity ceiling)
Writes (under --out, default <evidence>/boe):
  poam.json   - structured POA&M items
  poam.csv    - the same in an eMASS-import-style column layout (see compliance/templates/poam-template.csv)

eMASS POA&M column reference (CONFIRM against your eMASS instance's CAC-protected import template):
  Control Vulnerability Description | Security Control Number (NC/NA controls) | Office/Org |
  Security Checks (CCIs) | Resources Required | Scheduled Completion Date | Milestone with Completion Date |
  Milestone Changes | Source Identifying Control Vulnerability | Status | Comments |
  Raw Severity Value | Mitigations | Severity Value (adjusted) | Relevance of Threat | Likelihood |
  Impact | Impact Description | Residual Risk Level | Recommendations | Point of Contact

`Scheduled Completion Date` = first_seen + sla_days[severity]  (RAISE: High+ in prod => 21 days).
Findings whose adjusted/residual severity would exceed `raise_residual_risk_ceiling` are flagged
"AO escalation required (out of RAISE scope)".
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evidence_common import load_json, load_yaml, dump_json, now_iso, today, SEVERITY_RANK  # noqa: E402

SEV_TO_CAT = {"critical": "I", "high": "I", "medium": "II", "low": "III", "info": "III"}
SEV_TO_RISK = {"critical": "Very High", "high": "High", "medium": "Moderate", "low": "Low", "info": "Very Low"}
RISK_RANK = {"Very Low": 0, "Low": 1, "Moderate": 2, "High": 3, "Very High": 4}

CSV_COLUMNS = [
    "Control Vulnerability Description",
    "Security Control Number (NC/NA controls)",
    "Office/Org",
    "Security Checks (CCIs)",
    "Resources Required",
    "Scheduled Completion Date",
    "Milestone with Completion Date",
    "Milestone Changes",
    "Source Identifying Control Vulnerability",
    "Status",
    "Comments",
    "Raw Severity Value",
    "Mitigations",
    "Severity Value",
    "Relevance of Threat",
    "Likelihood",
    "Impact",
    "Impact Description",
    "Residual Risk Level",
    "Recommendations",
    "Point of Contact",
    # extra, non-eMASS bookkeeping columns (ignored on import; useful in the repo)
    "Finding Fingerprint",
    "Tool",
    "First Seen",
    "Age (days)",
    "Overdue",
]

SOURCE_LABEL = {
    "sast": "Pipeline SAST (CodeQL/Semgrep)",
    "sca": "Pipeline SCA / dependency scan (Trivy/Grype/OWASP Dependency-Check)",
    "container": "Pipeline container image scan (Trivy/Grype/Dockle/Hadolint)",
    "iac": "Pipeline IaC/config scan (Checkov/KICS/Trivy-config/kube-linter/Conftest)",
    "secrets": "Pipeline secrets scan (Gitleaks/TruffleHog)",
    "dast": "Pipeline DAST (OWASP ZAP)",
    "stig": "STIG/SCAP evaluation (OpenSCAP)",
    "license": "OSS license policy check",
    "supply-chain": "OpenSSF Scorecard (repo/supply-chain hygiene)",
}


def control_for_finding(f, controls):
    """Best-effort: find a control whose evidence gate matches the finding's gate, or whose id is
    a tag on the finding."""
    cid_tags = {t.upper() for t in f.get("tags", [])}
    for c in controls:
        if set(c.get("evidence_gates", [])) & {f.get("gate")}:
            return c["id"], c.get("ccis", [])
        if c["id"].upper() in cid_tags:
            return c["id"], c.get("ccis", [])
    # gate -> canonical control fallback
    fallback = {"sast": "SA-11", "sca": "RA-5", "container": "RA-5", "iac": "CM-6", "secrets": "IA-5",
                "dast": "SA-11", "stig": "CM-6", "license": "CM-10", "supply-chain": "SR-3"}
    return fallback.get(f.get("gate"), "RA-5"), []


def first_seen(f, history):
    """Return YYYY-MM-DD this fingerprint was first observed (from conmon history if available)."""
    fp = f["fingerprint"]
    for snap in history.get("snapshots", []) if isinstance(history, dict) else []:
        if fp in (snap.get("finding_fingerprints") or []):
            return snap.get("date")
    return today().isoformat()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--thresholds", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--office", default="(Program Office / responsible org)")
    ap.add_argument("--poc", default="(POC name / org / email)")
    a = ap.parse_args()

    ev_dir = Path(a.evidence)
    out_dir = Path(a.out) if a.out else ev_dir / "boe"
    out_dir.mkdir(parents=True, exist_ok=True)

    findings = load_json(ev_dir / "findings.json") or []
    controls = (load_json(out_dir / "controls.json") or {}).get("controls", [])
    history = load_json(out_dir / "conmon_history.json") or {}
    pol = load_yaml(a.thresholds) or {}
    poam_cfg = pol.get("poam") or {}
    min_sev = (poam_cfg.get("min_severity") or "low").lower()
    sla = poam_cfg.get("sla_days") or {"critical": 21, "high": 21, "medium": 90, "low": 365}
    ceiling = (poam_cfg.get("raise_residual_risk_ceiling") or "moderate")
    ceiling_rank = RISK_RANK.get(ceiling.title(), 2)
    escalate_overdue = poam_cfg.get("escalate_when_overdue", True)
    min_rank = SEVERITY_RANK.get(min_sev, 1)

    items = []
    for f in findings:
        if SEVERITY_RANK.get(f["severity"], 0) < min_rank:
            continue
        if f["severity"] == "info":
            continue
        cid, ccis = control_for_finding(f, controls)
        seen = first_seen(f, history)
        try:
            seen_d = dt.date.fromisoformat(seen)
        except Exception:
            seen_d = today()
        days_allowed = int(sla.get(f["severity"], 365))
        due = seen_d + dt.timedelta(days=days_allowed)
        age = (today() - seen_d).days
        overdue = today() > due
        residual = SEV_TO_RISK[f["severity"]]   # before mitigations; teams should adjust per the SCA Risk Assessment Guide
        out_of_raise_scope = RISK_RANK.get(residual, 2) > ceiling_rank
        status = "Ongoing"
        comments = []
        if overdue and escalate_overdue:
            comments.append(f"OVERDUE — exceeded the {days_allowed}-day remediation SLA on {due.isoformat()}; "
                            "AO exception or workload isolation required (RAISE).")
        if out_of_raise_scope:
            comments.append(f"Residual risk ({residual}) exceeds the RAISE ceiling ({ceiling.title()}) — "
                            "AO escalation required; this finding may place the application out of RAISE scope until mitigated.")
        if f.get("fix") == "fixed":
            comments.append("A fixed version is available — upgrade is the recommended remediation.")
        if f.get("cve"):
            comments.append("CVE(s): " + ", ".join(f["cve"]))
        item = {
            "fingerprint": f["fingerprint"],
            "control_vulnerability_description": f["title"] + (f"\n{f['description']}" if f.get("description") else ""),
            "security_control_number": cid,
            "office_org": a.office,
            "security_checks_ccis": ", ".join(ccis),
            "resources_required": "Developer/engineering effort; vendor patch / library upgrade where applicable.",
            "scheduled_completion_date": due.isoformat(),
            "milestones": [
                {"description": "Triage & confirm (assign owner, validate exploitability)", "date": (today() + dt.timedelta(days=min(3, days_allowed))).isoformat()},
                {"description": "Remediate (patch/upgrade/config change) & merge", "date": (today() + dt.timedelta(days=max(1, days_allowed - 5))).isoformat()},
                {"description": "Verify in next pipeline run & close", "date": due.isoformat()},
            ],
            "milestone_changes": "",
            "source_identifying_control_vulnerability": f"{SOURCE_LABEL.get(f['gate'], f['gate'])} — {f['tool']}"
                                                       + (f" (rule {f['rule_id']})" if f.get("rule_id") else ""),
            "status": status,
            "comments": " ".join(comments),
            "raw_severity": "CAT " + SEV_TO_CAT[f["severity"]] + f" ({f['severity'].title()})",
            "mitigations": "(Describe compensating controls / why not yet remediated, per the SCA Risk Assessment Guide.)",
            "severity_value": "CAT " + SEV_TO_CAT[f["severity"]],
            "relevance_of_threat": {"critical": "High", "high": "High", "medium": "Moderate", "low": "Low"}.get(f["severity"], "Low"),
            "likelihood": {"critical": "High", "high": "High", "medium": "Moderate", "low": "Low"}.get(f["severity"], "Low"),
            "impact": {"critical": "Very High", "high": "High", "medium": "Moderate", "low": "Low"}.get(f["severity"], "Low"),
            "impact_description": "(Impact to confidentiality/integrity/availability of the system — complete per categorization.)",
            "residual_risk_level": residual,
            "recommendations": "Apply the available fix / upgrade the affected component / remediate the misconfiguration; re-run the pipeline to verify.",
            "point_of_contact": a.poc,
            "tool": f["tool"],
            "gate": f["gate"],
            "first_seen": seen,
            "age_days": age,
            "overdue": overdue,
            "out_of_raise_scope": out_of_raise_scope,
            "evidence_run": f.get("run_url", ""),
        }
        items.append(item)

    # sort: out-of-scope first, then overdue, then severity (CAT I first), then age desc
    cat_order = {"I": 0, "II": 1, "III": 2}
    items.sort(key=lambda i: (not i["out_of_raise_scope"], not i["overdue"], cat_order.get(i["severity_value"].split()[-1], 3), -i["age_days"]))

    dump_json({
        "generated": now_iso(),
        "policy": {"min_severity": min_sev, "sla_days": sla, "raise_residual_risk_ceiling": ceiling},
        "total_items": len(items),
        "overdue": sum(1 for i in items if i["overdue"]),
        "out_of_raise_scope": sum(1 for i in items if i["out_of_raise_scope"]),
        "by_cat": {c: sum(1 for i in items if i["severity_value"].split()[-1] == c) for c in ("I", "II", "III")},
        "items": items,
    }, out_dir / "poam.json")

    with open(out_dir / "poam.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(CSV_COLUMNS)
        for i in items:
            ms = " | ".join(f"{m['description']} (target {m['date']})" for m in i["milestones"])
            w.writerow([
                i["control_vulnerability_description"], i["security_control_number"], i["office_org"],
                i["security_checks_ccis"], i["resources_required"], i["scheduled_completion_date"],
                ms, i["milestone_changes"], i["source_identifying_control_vulnerability"], i["status"],
                i["comments"], i["raw_severity"], i["mitigations"], i["severity_value"],
                i["relevance_of_threat"], i["likelihood"], i["impact"], i["impact_description"],
                i["residual_risk_level"], i["recommendations"], i["point_of_contact"],
                i["fingerprint"], i["tool"], i["first_seen"], i["age_days"], "YES" if i["overdue"] else "",
            ])

    print(f"POA&M: {len(items)} item(s) — {sum(1 for i in items if i['overdue'])} overdue, "
          f"{sum(1 for i in items if i['out_of_raise_scope'])} out-of-RAISE-scope. "
          f"CAT I/II/III = {[sum(1 for i in items if i['severity_value'].split()[-1] == c) for c in ('I','II','III')]}")


if __name__ == "__main__":
    main()
