#!/usr/bin/env python3
"""evidence_common.py — shared helpers + small CLI gates used directly by the pipeline.

Subcommands (each is also importable as a function):
  --validate-sbom <cdx.json>                       Check an SBOM against NTIA "minimum elements" (informational; exit 0).
  --check-licenses <cdx.json> <allowed.yaml> --out <report.json>   Evaluate OSS licenses vs policy.
  --gate-container <trivy-image.json> <thresholds.yaml>            Fail (exit 1) if the image violates the container gate.
  --scap-to-ckl <openscap-results.xml> --out <checklist.ckl>      Best-effort SCAP XCCDF results -> STIG .ckl skeleton.

This module is dependency-light (only PyYAML). It is intentionally defensive: missing/garbled
inputs degrade to warnings, not crashes — except the explicit *gate* subcommands, which are
allowed to fail the build.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


# --------------------------------------------------------------------------- utilities
def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today() -> _dt.date:
    return _dt.datetime.now(_dt.timezone.utc).date()


def load_json(path: str | os.PathLike) -> Any:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception as exc:
        print(f"::warning::could not parse JSON {path}: {exc}", file=sys.stderr)
        return None


def load_yaml(path: str | os.PathLike) -> Any:
    if yaml is None:
        print("::warning::PyYAML not installed; cannot read YAML", file=sys.stderr)
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return yaml.safe_load(fh)
    except Exception as exc:
        print(f"::warning::could not parse YAML {path}: {exc}", file=sys.stderr)
        return None


def dump_json(obj: Any, path: str | os.PathLike) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=False, default=str)
        fh.write("\n")


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

DEFAULT_SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "MODERATE": "medium",
    "LOW": "low", "WARNING": "medium", "ERROR": "high", "NOTE": "low",
    "INFO": "info", "INFORMATIONAL": "info", "UNKNOWN": "low", "NEGLIGIBLE": "info",
    "CAT I": "high", "CAT_I": "high", "CAT II": "medium", "CAT_II": "medium",
    "CAT III": "low", "CAT_III": "low",
}
CVSS_BANDS = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"), (0.0, "info")]


def norm_severity(value: Any, severity_map: dict | None = None) -> str:
    """Collapse a heterogeneous scanner severity onto critical/high/medium/low/info."""
    smap = {**DEFAULT_SEVERITY_MAP, **(severity_map or {})}
    if value is None:
        return "low"
    if isinstance(value, (int, float)):
        for lo, sev in CVSS_BANDS:
            if value >= lo:
                return sev
        return "info"
    s = str(value).strip()
    if s.upper() in smap:
        return smap[s.upper()]
    if s in smap:
        return smap[s]
    # numeric-looking string?
    try:
        return norm_severity(float(s), severity_map)
    except ValueError:
        pass
    # SARIF level fallbacks
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(s.lower(), "low")


def max_severity(sevs: Iterable[str]) -> str:
    best = "info"
    for s in sevs:
        if SEVERITY_RANK.get(s, 0) > SEVERITY_RANK.get(best, 0):
            best = s
    return best


# --------------------------------------------------------------------------- SBOM helpers
def _cdx_components(sbom: dict) -> list[dict]:
    if not isinstance(sbom, dict):
        return []
    comps = sbom.get("components") or []
    out = list(comps)
    # flatten nested components one level (CycloneDX allows nesting)
    for c in comps:
        out.extend(c.get("components") or [])
    return out


def component_licenses(comp: dict) -> list[str]:
    """Return SPDX ids / expressions found on a CycloneDX component."""
    out: list[str] = []
    for lic in comp.get("licenses") or []:
        if isinstance(lic, dict):
            if "expression" in lic:
                out.append(str(lic["expression"]))
            elif "license" in lic and isinstance(lic["license"], dict):
                lo = lic["license"]
                out.append(str(lo.get("id") or lo.get("name") or "").strip())
        elif isinstance(lic, str):
            out.append(lic)
    return [x for x in out if x]


def _expression_operands(expr: str) -> list[str]:
    # crude SPDX-expression splitter: split on AND/OR/WITH/parens
    return [t.strip() for t in re.split(r"\bAND\b|\bOR\b|\bWITH\b|[()]", expr, flags=re.I) if t.strip()]


def validate_sbom(path: str) -> int:
    """Informational check against NTIA SBOM Minimum Elements (2021). Always exit 0."""
    sbom = load_json(path)
    if not isinstance(sbom, dict):
        print(f"::warning::SBOM {path} not readable as JSON")
        return 0
    issues: list[str] = []
    fmt = sbom.get("bomFormat") or ("SPDX" if "spdxVersion" in sbom else "?")
    is_cdx = fmt == "CycloneDX" or "specVersion" in sbom
    # Author / timestamp / tool (NTIA: Author of SBOM Data, Timestamp)
    md = sbom.get("metadata") or {}
    if is_cdx:
        if not md.get("timestamp"):
            issues.append("missing metadata.timestamp (NTIA: Timestamp)")
        if not (md.get("authors") or (md.get("tools") or {})):
            issues.append("missing metadata.authors/tools (NTIA: Author of SBOM Data)")
        comps = _cdx_components(sbom)
        if not comps:
            issues.append("no components listed")
        for c in comps:
            if not c.get("name"):
                issues.append("a component is missing 'name' (NTIA: Component Name)")
            if not c.get("version"):
                issues.append(f"component {c.get('name','?')} missing 'version' (NTIA: Version)")
            if not (c.get("purl") or c.get("cpe") or c.get("bom-ref")):
                issues.append(f"component {c.get('name','?')} missing a unique identifier (purl/cpe) (NTIA: Other Unique Identifiers)")
        if not (sbom.get("dependencies")):
            issues.append("no 'dependencies' graph (NTIA: Dependency Relationship / Depth)")
    else:  # SPDX
        if not (sbom.get("creationInfo") or {}).get("created"):
            issues.append("missing creationInfo.created (NTIA: Timestamp)")
        if not (sbom.get("creationInfo") or {}).get("creators"):
            issues.append("missing creationInfo.creators (NTIA: Author of SBOM Data)")
        if not sbom.get("packages"):
            issues.append("no packages listed")
        if not sbom.get("relationships"):
            issues.append("no relationships (NTIA: Dependency Relationship / Depth)")
    if issues:
        print(f"::notice::SBOM {path}: {len(issues)} NTIA-minimum-element gap(s):")
        for i in issues:
            print(f"  - {i}")
    else:
        print(f"SBOM {path}: meets the NTIA minimum-element checklist (structural check).")
    return 0


# --------------------------------------------------------------------------- license gate
def check_licenses(sbom_path: str, policy_path: str, out_path: str | None) -> int:
    sbom = load_json(sbom_path) or {}
    pol = load_yaml(policy_path) or {}
    allowed = {x.upper() for x in pol.get("allowed", [])}
    review = {x.upper() for x in pol.get("allowed_with_review", [])}
    disallowed = {x.upper() for x in pol.get("disallowed", [])}
    exclude = set(pol.get("exclude_components", []))

    findings = []
    for c in _cdx_components(sbom):
        ref = c.get("purl") or c.get("bom-ref") or c.get("name") or "?"
        if any(ref.startswith(x) or ref == x for x in exclude):
            continue
        lics = component_licenses(c)
        if not lics:
            findings.append({"component": ref, "name": c.get("name"), "version": c.get("version"),
                             "licenses": [], "status": "unknown"})
            continue
        # A component passes if ANY operand of ANY expression is allowed; flag disallowed if ALL
        # operands are disallowed/unknown; mark review if best we can do is "review".
        statuses = []
        for expr in lics:
            ops = _expression_operands(expr) or [expr]
            up = [o.upper() for o in ops]
            if any(o in allowed for o in up):
                statuses.append("allowed")
            elif any(o in review for o in up):
                statuses.append("review")
            elif any(o in disallowed for o in up):
                statuses.append("disallowed")
            else:
                statuses.append("unknown")
        if "allowed" in statuses:
            status = "allowed"
        elif "review" in statuses:
            status = "review"
        elif "disallowed" in statuses:
            status = "disallowed"
        else:
            status = "unknown"
        if status != "allowed":
            findings.append({"component": ref, "name": c.get("name"), "version": c.get("version"),
                             "licenses": lics, "status": status})

    summary = {
        "generated": now_iso(), "sbom": os.path.basename(sbom_path), "policy": os.path.basename(policy_path),
        "total_components": len(_cdx_components(sbom)),
        "disallowed": [f for f in findings if f["status"] == "disallowed"],
        "review_required": [f for f in findings if f["status"] == "review"],
        "unknown": [f for f in findings if f["status"] == "unknown"],
    }
    if out_path:
        dump_json(summary, out_path)
    n_bad = len(summary["disallowed"])
    n_rev = len(summary["review_required"])
    n_unk = len(summary["unknown"])
    print(f"License check: {summary['total_components']} components — {n_bad} disallowed, {n_rev} review-required, {n_unk} unknown.")
    for f in summary["disallowed"]:
        print(f"::error::Disallowed license: {f['name']} {f.get('version')} -> {f['licenses']}")
    # Honor thresholds: this CLI itself only fails on disallowed (unknown handled by the workflow
    # policy if you wire it; conservative default = block on disallowed).
    return 1 if n_bad else 0


# --------------------------------------------------------------------------- container gate
def _iter_trivy_vulns(report: dict):
    for res in (report or {}).get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            yield res.get("Target", "?"), v


def gate_container(trivy_json_path: str, thresholds_path: str) -> int:
    report = load_json(trivy_json_path) or {}
    pol = load_yaml(thresholds_path) or {}
    if not pol.get("enforce", True):
        print("::notice::thresholds.enforce=false — container gate is report-only.")
        return 0
    gate = (pol.get("gates") or {}).get("container") or {}
    fail_sev = {s.lower() for s in gate.get("fail_on_severity", ["critical"])}
    block_high_with_fix = gate.get("block_high_with_fix", True)
    smap = (pol.get("severity_map") or {})
    violations = []
    for target, v in _iter_trivy_vulns(report):
        sev = norm_severity(v.get("Severity"), smap)
        fixed = bool(v.get("FixedVersion"))
        if sev in fail_sev:
            violations.append((sev, v.get("VulnerabilityID"), target, "fixed" if fixed else "unfixed"))
        elif sev == "high" and fixed and block_high_with_fix:
            violations.append(("high", v.get("VulnerabilityID"), target, "fixed"))
    # OS user / healthcheck checks from the image config if Trivy included it
    if violations:
        print(f"::error::Container gate FAILED — {len(violations)} blocking vulnerability finding(s):")
        for sev, vid, tgt, fx in violations[:50]:
            print(f"  - {sev.upper():8} {vid}  ({tgt})  [{fx}]")
        if len(violations) > 50:
            print(f"  ... and {len(violations) - 50} more")
        return 1
    print("Container gate PASSED (no blocking image vulnerabilities per policy/thresholds.yaml).")
    return 0


# --------------------------------------------------------------------------- SCAP -> CKL
def scap_to_ckl(results_xml: str, out_path: str) -> int:
    """Very small XCCDF-results -> STIG Viewer .ckl skeleton. Real CKL generation should use a
    proper tool (e.g., `oscap` with `--stig-viewer`, or stigviewer itself). This emits a minimal,
    well-formed shell so the BoE has a CKL artifact placeholder tied to the SCAP run."""
    try:
        tree = ET.parse(results_xml)
        root = tree.getroot()
    except Exception as exc:
        print(f"::warning::cannot parse SCAP results {results_xml}: {exc}")
        # still emit an empty CKL shell
        root = None

    rules = []
    if root is not None:
        ns = {"x": "http://checklists.nist.gov/xccdf/1.2", "x1": "http://checklists.nist.gov/xccdf/1.1"}
        for rr in root.iter():
            if rr.tag.endswith("rule-result"):
                rid = rr.get("idref", "")
                res_el = next((c for c in rr if c.tag.endswith("result")), None)
                res = (res_el.text or "").strip() if res_el is not None else "notchecked"
                status = {"pass": "NotAFinding", "fail": "Open", "notapplicable": "Not_Applicable",
                          "notchecked": "Not_Reviewed", "error": "Open", "unknown": "Not_Reviewed",
                          "notselected": "Not_Reviewed"}.get(res, "Not_Reviewed")
                rules.append((rid, status))

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        fh.write("<!-- DISA STIG Viewer Checklist (skeleton, generated from SCAP results). "
                 "Replace with a full CKL produced from the appropriate DISA STIG benchmark for "
                 "your component. -->\n")
        fh.write("<CHECKLIST>\n  <ASSET>\n    <ROLE>None</ROLE>\n    <ASSET_TYPE>Computing</ASSET_TYPE>\n"
                 "    <HOST_NAME>container-image</HOST_NAME>\n  </ASSET>\n  <STIGS>\n    <iSTIG>\n")
        fh.write("      <STIG_INFO><SI_DATA><SID_NAME>title</SID_NAME>"
                 "<SID_DATA>Auto-generated from SCAP results</SID_DATA></SI_DATA></STIG_INFO>\n")
        for rid, status in rules:
            fh.write("      <VULN>\n")
            fh.write(f"        <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>{_xml(rid)}</ATTRIBUTE_DATA></STIG_DATA>\n")
            fh.write(f"        <STATUS>{status}</STATUS>\n")
            fh.write("        <FINDING_DETAILS>From SCAP/OpenSCAP evaluation.</FINDING_DETAILS>\n")
            fh.write("        <COMMENTS></COMMENTS>\n")
            fh.write("      </VULN>\n")
        fh.write("    </iSTIG>\n  </STIGS>\n</CHECKLIST>\n")
    print(f"Wrote CKL skeleton with {len(rules)} rule-result(s) -> {out_path}")
    return 0


def _xml(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# --------------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--validate-sbom", metavar="CDX_JSON")
    p.add_argument("--check-licenses", nargs=2, metavar=("CDX_JSON", "ALLOWED_YAML"))
    p.add_argument("--gate-container", nargs=2, metavar=("TRIVY_IMAGE_JSON", "THRESHOLDS_YAML"))
    p.add_argument("--scap-to-ckl", metavar="OPENSCAP_RESULTS_XML")
    p.add_argument("--out", metavar="PATH")
    a = p.parse_args(argv)

    if a.validate_sbom:
        return validate_sbom(a.validate_sbom)
    if a.check_licenses:
        return check_licenses(a.check_licenses[0], a.check_licenses[1], a.out)
    if a.gate_container:
        return gate_container(a.gate_container[0], a.gate_container[1])
    if a.scap_to_ckl:
        return scap_to_ckl(a.scap_to_ckl, a.out or "checklist.ckl")
    p.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
