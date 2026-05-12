#!/usr/bin/env python3
"""update_conmon.py — append a dated continuous-monitoring snapshot to conmon_history.json.

Evidence: CA-7 (Continuous Monitoring), cATO Pillar 1 (continuous monitoring of RMF controls),
RAISE 2.0 ConMon / quarterly-review trend data.

The history file is committed back / re-published as part of the Body of Evidence each run, so the
trend persists across runs. Each snapshot records the severity counts, control-result counts, the
POA&M size (and overdue count), and the set of finding fingerprints observed (so generate_poam.py
can compute each finding's first-seen date / age).

To keep the file bounded, finding-fingerprint sets are only retained for the most recent N
snapshots (default 60); older snapshots keep their aggregate numbers.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evidence_common import load_json, dump_json, now_iso, today  # noqa: E402

RETAIN_FINGERPRINTS = 60


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--history", required=True, help="path to conmon_history.json (created if absent)")
    ap.add_argument("--commit", default="")
    ap.add_argument("--run-id", default="")
    a = ap.parse_args()

    ev_dir = Path(a.evidence)
    findings = load_json(ev_dir / "findings.json") or []
    index = load_json(ev_dir / "evidence_index.json") or {}
    boe = ev_dir / "boe"
    controls_summary = load_json(boe / "controls_summary.json") or {}
    poam = load_json(boe / "poam.json") or {}

    hist_path = Path(a.history)
    history = load_json(hist_path) if hist_path.exists() else None
    if not isinstance(history, dict):
        history = {"created": now_iso(), "snapshots": []}

    fps = sorted({f["fingerprint"] for f in findings})
    snap = {
        "date": today().isoformat(),
        "timestamp": now_iso(),
        "commit": a.commit,
        "run_id": a.run_id,
        "run_url": index.get("run_url", ""),
        "gates_executed": index.get("gates_executed", []),
        "findings_total": len(findings),
        "findings_by_severity": index.get("by_severity", {}),
        "findings_by_gate": index.get("by_gate", {}),
        "controls_total": controls_summary.get("total_controls", 0),
        "controls_results": controls_summary.get("test_results", {}),
        "controls_compliant_pct_of_assessed": controls_summary.get("compliant_pct_of_assessed", 0.0),
        "controls_automated_coverage_pct": controls_summary.get("automated_assessment_coverage_pct", 0.0),
        "poam_open": poam.get("total_items", 0),
        "poam_overdue": poam.get("overdue", 0),
        "poam_out_of_raise_scope": poam.get("out_of_raise_scope", 0),
        "poam_by_cat": poam.get("by_cat", {}),
        "sbom_component_count": index.get("sbom_component_count", 0),
        "finding_fingerprints": fps,
    }

    # If there's already a snapshot for today, replace it (idempotent for multiple runs/day).
    history["snapshots"] = [s for s in history["snapshots"] if s.get("date") != snap["date"]]
    history["snapshots"].append(snap)
    history["snapshots"].sort(key=lambda s: s.get("timestamp", s.get("date", "")))

    # Trim fingerprint sets on older snapshots.
    for s in history["snapshots"][:-RETAIN_FINGERPRINTS]:
        s.pop("finding_fingerprints", None)

    history["updated"] = now_iso()
    dump_json(history, hist_path)
    print(f"ConMon snapshot for {snap['date']}: {len(findings)} findings "
          f"({index.get('by_severity', {})}), POA&M open={snap['poam_open']} overdue={snap['poam_overdue']}; "
          f"history now has {len(history['snapshots'])} snapshot(s).")


if __name__ == "__main__":
    main()
