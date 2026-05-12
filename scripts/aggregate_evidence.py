#!/usr/bin/env python3
"""aggregate_evidence.py — normalize every scanner output in raw-evidence/ into one findings set.

Input:  a directory tree of artifacts downloaded from the pipeline jobs (SARIF, Trivy/Grype JSON,
        OWASP Dependency-Check JSON, ZAP JSON, Checkov/KICS JSON, Gitleaks/TruffleHog JSON,
        OpenSSF Scorecard JSON, Dockle JSON, OpenSCAP XML, CKL, SBOMs).
Output (under --out):
        findings.json          - flat list of normalized findings (deduplicated)
        evidence_index.json    - which gates ran, which artifact files were ingested, counts
        sbom/                  - copies of every SBOM found (SPDX + CycloneDX, source + image)
        sbom/components.json   - merged, deduplicated component list (for the HW/SW baseline)

Each normalized finding:
  { "fingerprint": str, "gate": str, "tool": str, "severity": critical|high|medium|low|info,
    "title": str, "description": str, "location": str, "component": str|None, "version": str|None,
    "cve": [str], "cwe": [str], "fix": "fixed"|"unfixed"|None, "rule_id": str|None,
    "tags": [str], "run_url": str, "raw_artifact": str }
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# allow `import evidence_common` whether run from repo root or scripts/
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evidence_common import load_json, dump_json, norm_severity, now_iso, today  # noqa: E402

GATE_BY_TOOL = {
    "codeql": "sast", "semgrep": "sast",
    "trivy-fs": "sca", "grype-fs": "sca", "owasp-dependency-check": "sca", "trivy": "sca",
    "trivy-image": "container", "grype-image": "container", "hadolint": "container",
    "dockle": "container",
    "checkov": "iac", "kics": "iac", "trivy-config": "iac", "kube-linter": "iac", "conftest": "iac",
    "gitleaks": "secrets", "trufflehog": "secrets",
    "zap": "dast", "owasp-zap": "dast",
    "openscap": "stig", "stig-checklist": "stig",
    "license-policy": "license",
    "openssf-scorecard": "supply-chain",
}


def fingerprint(*parts: object) -> str:
    return hashlib.sha256("||".join(str(p) for p in parts).encode("utf-8", "replace")).hexdigest()[:24]


def mk(gate, tool, severity, title, *, description="", location="", component=None, version=None,
       cve=None, cwe=None, fix=None, rule_id=None, tags=None, run_url="", raw=""):
    cve = sorted(set(cve or []))
    cwe = sorted(set(cwe or []))
    return {
        "fingerprint": fingerprint(tool, rule_id or title, location, component, version, ",".join(cve)),
        "gate": gate, "tool": tool, "severity": norm_severity(severity),
        "title": (title or "").strip()[:300],
        "description": (description or "").strip()[:4000],
        "location": (location or "").strip(),
        "component": component, "version": version,
        "cve": cve, "cwe": cwe, "fix": fix, "rule_id": rule_id,
        "tags": sorted(set(tags or [])), "run_url": run_url, "raw_artifact": raw,
    }


# --------------------------------------------------------------------------- SARIF
def parse_sarif(path: Path, run_url: str):
    data = load_json(path)
    out = []
    if not isinstance(data, dict):
        return out
    for run in data.get("runs") or []:
        tool_name = (((run.get("tool") or {}).get("driver") or {}).get("name") or "sarif").lower()
        # Normalize tool names — SARIF drivers vary ("Semgrep OSS", "Semgrep CE", "CodeQL", "Trivy",
        # "Checkov", "KICS", "kube-linter", "Hadolint", "Scorecard", ...). Substring match so we
        # don't lose the gate attribution to the catch-all "other" bucket.
        tn = tool_name
        if "semgrep" in tn:
            tool = "semgrep"
        elif "codeql" in tn:
            tool = "codeql"
        elif "trivy" in tn:
            tool = "trivy"
        elif "checkov" in tn:
            tool = "checkov"
        elif "kics" in tn:
            tool = "kics"
        elif "kube-linter" in tn or "kubelinter" in tn:
            tool = "kube-linter"
        elif "hadolint" in tn:
            tool = "hadolint"
        elif "scorecard" in tn:
            tool = "openssf-scorecard"
        else:
            tool = tn
        # disambiguate trivy fs vs image / checkov by category
        cat = (run.get("automationDetails") or {}).get("id") or ""
        if tool == "trivy" and "image" in (cat + str(path)).lower():
            tool = "trivy-image"
        elif tool == "trivy":
            tool = "trivy-fs"
        gate = GATE_BY_TOOL.get(tool, "other")
        # rule metadata index
        rules = {}
        for r in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []:
            rules[r.get("id")] = r
        for res in run.get("results") or []:
            rid = res.get("ruleId") or ""
            rule = rules.get(rid, {})
            level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
            # severity: prefer security-severity property if present
            sec = ((rule.get("properties") or {}).get("security-severity")
                   or (res.get("properties") or {}).get("security-severity"))
            sev = norm_severity(float(sec)) if sec else norm_severity(level)
            msg = ((res.get("message") or {}).get("text") or rule.get("name") or rid or "").strip()
            loc = ""
            for l in res.get("locations") or []:
                pl = (l.get("physicalLocation") or {})
                uri = ((pl.get("artifactLocation") or {}).get("uri") or "")
                line = ((pl.get("region") or {}).get("startLine") or "")
                if uri:
                    loc = f"{uri}:{line}" if line else uri
                    break
            cwe = re.findall(r"CWE[-_ ]?(\d+)", json.dumps(rule.get("properties") or {}) + " " + json.dumps(res.get("properties") or {}) + " " + (rule.get("fullDescription", {}) or {}).get("text", "") + " " + (rule.get("help", {}) or {}).get("text", ""), re.I)
            cwe = [f"CWE-{n}" for n in cwe]
            cve = re.findall(r"CVE-\d{4}-\d{4,7}", msg + " " + json.dumps(res.get("properties") or {}), re.I)
            tags = [str(t) for t in (rule.get("properties") or {}).get("tags") or []]
            out.append(mk(gate, tool, sev, msg or rid, description=(rule.get("fullDescription", {}) or {}).get("text", ""),
                          location=loc, cve=[c.upper() for c in cve], cwe=cwe, rule_id=rid, tags=tags,
                          run_url=run_url, raw=str(path.name)))
    return out


# --------------------------------------------------------------------------- Trivy JSON
def parse_trivy(path: Path, run_url: str):
    data = load_json(path)
    out = []
    if not isinstance(data, dict):
        return out
    is_image = (data.get("ArtifactType") in ("container_image", "image")) or "image" in path.name.lower()
    is_config = data.get("ArtifactType") == "config" or "config" in path.name.lower()
    if is_config:
        tool, gate = "trivy-config", "iac"
    elif is_image:
        tool, gate = "trivy-image", "container"
    else:
        tool, gate = "trivy-fs", "sca"
    for res in data.get("Results") or []:
        target = res.get("Target", "?")
        for v in res.get("Vulnerabilities") or []:
            out.append(mk(gate, tool, v.get("Severity"), f"{v.get('VulnerabilityID')} in {v.get('PkgName')}",
                          description=v.get("Title") or v.get("Description") or "",
                          location=target, component=v.get("PkgName"), version=v.get("InstalledVersion"),
                          cve=[v.get("VulnerabilityID")] if str(v.get("VulnerabilityID", "")).startswith("CVE") else [],
                          cwe=[c for c in (v.get("CweIDs") or [])],
                          fix="fixed" if v.get("FixedVersion") else "unfixed",
                          rule_id=v.get("VulnerabilityID"), tags=["dependency-vuln"], run_url=run_url, raw=path.name))
        for m in res.get("Misconfigurations") or []:
            out.append(mk("iac" if not is_image else gate, tool, m.get("Severity"), m.get("Title") or m.get("ID"),
                          description=m.get("Description") or m.get("Message") or "",
                          location=f"{target}:{(m.get('CauseMetadata') or {}).get('StartLine','')}",
                          rule_id=m.get("ID"), tags=["misconfig"], run_url=run_url, raw=path.name))
        for s in res.get("Secrets") or []:
            out.append(mk("secrets", tool, s.get("Severity") or "HIGH", f"Secret: {s.get('Title') or s.get('RuleID')}",
                          location=f"{target}:{s.get('StartLine','')}", rule_id=s.get("RuleID"),
                          tags=["secret"], run_url=run_url, raw=path.name))
        # NOTE: Trivy also emits a `Licenses` block, but its image-license output is dominated by
        # the base image's (unactionable) Debian/Alpine GPL/LGPL packages — hundreds of "findings"
        # that just add noise. The authoritative license signal is the dedicated `license-compliance`
        # gate (CycloneDX SBOM evaluated against policy/allowed-licenses.yaml), so Trivy's License
        # block is intentionally NOT ingested here.
    return out


# --------------------------------------------------------------------------- Grype JSON
def parse_grype(path: Path, run_url: str):
    data = load_json(path)
    out = []
    if not isinstance(data, dict):
        return out
    is_image = "image" in path.name.lower()
    tool, gate = ("grype-image", "container") if is_image else ("grype-fs", "sca")
    for m in data.get("matches") or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        sev = vuln.get("severity")
        fixstate = ((vuln.get("fix") or {}).get("state") or "").lower()
        out.append(mk(gate, tool, sev, f"{vuln.get('id')} in {art.get('name')}",
                      description=vuln.get("description") or "",
                      location=";".join(l.get("path", "") for l in art.get("locations") or []) or art.get("name", ""),
                      component=art.get("name"), version=art.get("version"),
                      cve=[vuln.get("id")] if str(vuln.get("id", "")).startswith("CVE") else [],
                      fix="fixed" if fixstate == "fixed" else ("unfixed" if fixstate in ("not-fixed", "unknown", "wont-fix") else None),
                      rule_id=vuln.get("id"), tags=["dependency-vuln"], run_url=run_url, raw=path.name))
    return out


# --------------------------------------------------------------------------- OWASP Dependency-Check
def parse_dependency_check(path: Path, run_url: str):
    data = load_json(path)
    out = []
    if not isinstance(data, dict):
        return out
    for dep in data.get("dependencies") or []:
        name = dep.get("fileName") or "?"
        for vuln in (dep.get("vulnerabilities") or []):
            sev = (vuln.get("severity") or "").upper() or norm_severity((vuln.get("cvssv3") or {}).get("baseScore") or (vuln.get("cvssv2") or {}).get("score"))
            cwes = vuln.get("cwes") or []
            out.append(mk("sca", "owasp-dependency-check", sev, f"{vuln.get('name')} in {name}",
                          description=vuln.get("description") or "", location=dep.get("filePath") or name,
                          component=name, cve=[vuln.get("name")] if str(vuln.get("name", "")).startswith("CVE") else [],
                          cwe=[c if c.startswith("CWE") else f"CWE-{c}" for c in cwes],
                          rule_id=vuln.get("name"), tags=["dependency-vuln"], run_url=run_url, raw=path.name))
    return out


# --------------------------------------------------------------------------- ZAP JSON
def parse_zap(path: Path, run_url: str):
    data = load_json(path)
    out = []
    if not isinstance(data, dict):
        return out
    riskmap = {"3": "high", "2": "medium", "1": "low", "0": "info", "high": "high", "medium": "medium", "low": "low", "informational": "info"}
    for site in data.get("site") or []:
        for a in site.get("alerts") or []:
            sev = riskmap.get(str(a.get("riskcode", a.get("risk", "1"))).lower(), "low")
            cwe = a.get("cweid")
            n_inst = len(a.get("instances") or [])
            out.append(mk("dast", "owasp-zap", sev, a.get("alert") or a.get("name") or "ZAP alert",
                          description=re.sub("<[^<]+?>", "", a.get("desc") or "")[:2000],
                          location=(site.get("@name") or "") + (f" ({n_inst} instances)" if n_inst else ""),
                          cwe=[f"CWE-{cwe}"] if cwe and str(cwe) != "-1" else [],
                          rule_id=str(a.get("pluginid") or ""), tags=["dast"], run_url=run_url, raw=path.name))
    return out


# --------------------------------------------------------------------------- Checkov / KICS / Conftest JSON
def parse_checkov(path: Path, run_url: str):
    data = load_json(path)
    out = []
    if not isinstance(data, (dict, list)):
        return out
    blocks = data if isinstance(data, list) else [data]
    for b in blocks:
        results = (b.get("results") or {}) if isinstance(b, dict) else {}
        for f in results.get("failed_checks") or []:
            sev = (f.get("severity") or "MEDIUM")
            out.append(mk("iac", "checkov", sev, f.get("check_name") or f.get("check_id"),
                          description=(f.get("guideline") or ""),
                          location=f"{f.get('file_path','')}:{(f.get('file_line_range') or [''])[0]}",
                          rule_id=f.get("check_id"), tags=["misconfig", f.get("check_class", "")], run_url=run_url, raw=path.name))
    return out


def parse_kics(path: Path, run_url: str):
    data = load_json(path)
    out = []
    if not isinstance(data, dict):
        return out
    for q in data.get("queries") or []:
        sev = q.get("severity") or "MEDIUM"
        for f in q.get("files") or []:
            out.append(mk("iac", "kics", sev, q.get("query_name") or "KICS finding",
                          description=q.get("description") or "",
                          location=f"{f.get('file_name','')}:{f.get('line','')}",
                          rule_id=q.get("query_id"), tags=["misconfig", q.get("platform", "")], run_url=run_url, raw=path.name))
    return out


def parse_conftest(path: Path, run_url: str):
    data = load_json(path)
    out = []
    if not isinstance(data, list):
        return out
    for r in data:
        fn = r.get("filename", "?")
        for fail in r.get("failures") or []:
            out.append(mk("iac", "conftest", "high", str(fail.get("msg") or fail), location=fn,
                          rule_id="conftest-deny", tags=["policy-as-code"], run_url=run_url, raw=path.name))
        for w in r.get("warnings") or []:
            out.append(mk("iac", "conftest", "medium", str(w.get("msg") or w), location=fn,
                          rule_id="conftest-warn", tags=["policy-as-code"], run_url=run_url, raw=path.name))
    return out


# --------------------------------------------------------------------------- Gitleaks / TruffleHog
def parse_gitleaks(path: Path, run_url: str):
    data = load_json(path)
    out = []
    items = data if isinstance(data, list) else (data.get("findings") if isinstance(data, dict) else None) or []
    for f in items:
        out.append(mk("secrets", "gitleaks", "critical", f"Secret: {f.get('RuleID') or f.get('Description')}",
                      description=f.get("Description") or "",
                      location=f"{f.get('File','')}:{f.get('StartLine','')} ({f.get('Commit','')[:8]})",
                      rule_id=f.get("RuleID"), tags=["secret"], run_url=run_url, raw=path.name))
    return out


def parse_trufflehog(path: Path, run_url: str):
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    f = json.loads(line)
                except Exception:
                    continue
                if not isinstance(f, dict):
                    continue
                det = f.get("DetectorName") or f.get("DetectorType") or "secret"
                verified = (f.get("Verified") is True)
                src = f.get("SourceMetadata") or {}
                loc = json.dumps(src)[:200]
                out.append(mk("secrets", "trufflehog", "critical" if verified else "high",
                              f"Secret: {det}" + (" (verified)" if verified else " (unverified)"),
                              location=loc, rule_id=str(det), tags=["secret"] + (["verified"] if verified else []),
                              run_url=run_url, raw=path.name))
    except Exception:
        pass
    return out


# --------------------------------------------------------------------------- Dockle / Scorecard / OpenSCAP / CKL
def parse_dockle(path: Path, run_url: str):
    data = load_json(path)
    out = []
    if not isinstance(data, dict):
        return out
    levelmap = {"FATAL": "critical", "WARN": "medium", "INFO": "info", "SKIP": "info", "PASS": "info"}
    for d in data.get("details") or []:
        lvl = d.get("level", "INFO")
        if lvl in ("PASS", "SKIP"):
            continue
        out.append(mk("container", "dockle", levelmap.get(lvl, "low"), f"{d.get('code')}: {d.get('title')}",
                      description="; ".join(str(a) for a in d.get("alerts") or []),
                      rule_id=d.get("code"), tags=["container-hardening", "CIS"], run_url=run_url, raw=path.name))
    return out


def parse_scorecard(path: Path, run_url: str):
    data = load_json(path)
    out = []
    if not isinstance(data, dict):
        return out
    overall = data.get("score")
    for c in data.get("checks") or []:
        score = c.get("score")
        if score is None or score < 0:
            continue
        if score >= 8:
            continue  # only surface weak checks
        sev = "high" if score <= 3 else ("medium" if score <= 6 else "low")
        out.append(mk("supply-chain", "openssf-scorecard", sev, f"Scorecard: {c.get('name')} = {score}/10",
                      description=c.get("reason") or "", rule_id=c.get("name"),
                      tags=["supply-chain", "repo-hygiene"], run_url=run_url, raw=path.name))
    if overall is not None:
        out.append(mk("supply-chain", "openssf-scorecard", "info", f"OpenSSF Scorecard overall score: {overall}/10",
                      tags=["supply-chain", "score"], run_url=run_url, raw=path.name))
    return out


def parse_openscap_xml(path: Path, run_url: str):
    out = []
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return out
    for rr in root.iter():
        if not rr.tag.endswith("rule-result"):
            continue
        rid = rr.get("idref", "")
        sev = rr.get("severity", "medium")
        res_el = next((c for c in rr if c.tag.endswith("result")), None)
        res = (res_el.text or "").strip() if res_el is not None else "notchecked"
        if res not in ("fail", "error"):
            continue
        out.append(mk("stig", "openscap", sev, f"STIG/SCAP fail: {rid}", location=str(path.name),
                      rule_id=rid, tags=["stig", "scap"], run_url=run_url, raw=path.name))
    return out


def parse_ckl(path: Path, run_url: str):
    out = []
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return out
    for vuln in root.iter("VULN"):
        status = (vuln.findtext("STATUS") or "").strip()
        if status != "Open":
            continue
        attrs = {}
        for sd in vuln.findall("STIG_DATA"):
            attrs[(sd.findtext("VULN_ATTRIBUTE") or "").strip()] = (sd.findtext("ATTRIBUTE_DATA") or "").strip()
        sev = {"high": "high", "medium": "medium", "low": "low"}.get((attrs.get("Severity") or "medium").lower(), "medium")
        out.append(mk("stig", "stig-checklist", sev, f"STIG Open: {attrs.get('Rule_Ver') or attrs.get('Rule_ID') or attrs.get('Vuln_Num')}",
                      description=attrs.get("Rule_Title") or "", rule_id=attrs.get("Rule_ID") or attrs.get("Vuln_Num"),
                      tags=["stig"], run_url=run_url, raw=path.name))
    return out


def parse_license_report(path: Path, run_url: str):
    data = load_json(path)
    out = []
    if not isinstance(data, dict):
        return out
    for f in data.get("disallowed") or []:
        out.append(mk("license", "license-policy", "high", f"Disallowed license: {f.get('name')} {f.get('version') or ''}",
                      description=f"licenses={f.get('licenses')}", component=f.get("name"), version=f.get("version"),
                      rule_id="license-disallowed", tags=["license"], run_url=run_url, raw=path.name))
    for f in data.get("review_required") or []:
        out.append(mk("license", "license-policy", "low", f"License needs review: {f.get('name')} {f.get('version') or ''}",
                      description=f"licenses={f.get('licenses')}", component=f.get("name"), version=f.get("version"),
                      rule_id="license-review", tags=["license"], run_url=run_url, raw=path.name))
    return out


def parse_codescanning_alerts(path: Path, run_url: str):
    """GitHub code-scanning alerts (from `gh api repos/.../code-scanning/alerts`). Used to bring
    CodeQL (which runs in a separate workflow and uploads to code scanning, not to a workflow
    artifact) into the consolidated findings. Other tools' alerts are skipped here because their
    SARIF is already parsed directly from the run artifacts (avoids double-counting)."""
    data = load_json(path)
    out = []
    if not isinstance(data, list):
        return out
    sevmap = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
              "error": "high", "warning": "medium", "note": "low", "none": "info", "warn": "medium"}
    for a in data:
        if not isinstance(a, dict) or a.get("state") not in (None, "open"):
            continue
        tool = ((a.get("tool") or {}).get("name") or "").strip()
        if "codeql" not in tool.lower():
            continue  # other tools' findings come from their SARIF artifacts directly
        rule = a.get("rule") or {}
        sev = sevmap.get((rule.get("security_severity_level") or rule.get("severity") or "").lower(), "low")
        loc = ""
        inst = a.get("most_recent_instance") or {}
        ploc = inst.get("location") or {}
        if ploc.get("path"):
            loc = f"{ploc['path']}:{ploc.get('start_line','')}".rstrip(":")
        msg = (inst.get("message") or {}).get("text") or rule.get("description") or rule.get("name") or rule.get("id") or "CodeQL alert"
        cwe = []
        for t in (rule.get("tags") or []):
            m = re.search(r"cwe[-/](\d+)", str(t), re.I)
            if m:
                cwe.append(f"CWE-{int(m.group(1))}")
        out.append(mk("sast", "codeql", sev, msg, description=rule.get("full_description") or rule.get("description") or "",
                      location=loc, rule_id=rule.get("id"), cwe=cwe,
                      tags=["sast", "code-scanning"], run_url=a.get("html_url") or run_url, raw=path.name))
    return out


# --------------------------------------------------------------------------- SBOM collection
def collect_sboms(root: Path, out_dir: Path):
    sbom_dir = out_dir / "sbom"
    sbom_dir.mkdir(parents=True, exist_ok=True)
    found = []
    components = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        n = p.name.lower()
        is_sbom = (n.endswith(".spdx.json") or n.endswith(".cdx.json")
                   or (n.endswith(".json") and ("sbom" in n or "spdx" in n or "cyclonedx" in n or "cdx" in n)))
        if not is_sbom:
            # peek for cyclonedx/spdx markers
            try:
                head = p.open("rb").read(400).decode("utf-8", "replace")
            except Exception:
                continue
            if '"bomFormat"' in head and "CycloneDX" in head:
                is_sbom = True
            elif '"spdxVersion"' in head:
                is_sbom = True
        if not is_sbom:
            continue
        data = load_json(p)
        if not isinstance(data, dict):
            continue
        dest = sbom_dir / p.name
        # avoid clobbering identical-named files from different jobs
        i = 1
        while dest.exists():
            dest = sbom_dir / f"{p.stem}.{i}{p.suffix}"
            i += 1
        try:
            shutil.copy2(p, dest)
        except Exception:
            dump_json(data, dest)
        found.append(dest.name)
        # Merge components into a package-level inventory for the eMASS HW/SW baseline. Syft's
        # image SBOMs also list every *file* in the image (type "file") — thousands of them — which
        # is not a software baseline; we keep only real packages/applications/the OS.
        keep_types = {"library", "application", "framework", "operating-system", "container", "module"}
        if data.get("bomFormat") == "CycloneDX" or "specVersion" in data:
            for c in (data.get("components") or []):
                ctype = (c.get("type") or "").lower()
                purl = c.get("purl")
                if ctype not in keep_types:
                    continue
                if not (purl or c.get("version")):       # skip the bare repo-root pseudo-component
                    continue
                key = purl or f"{c.get('name')}@{c.get('version')}"
                if key and key not in components:
                    components[key] = {"name": c.get("name"), "version": c.get("version"),
                                       "type": c.get("type"), "purl": purl,
                                       "licenses": [l.get("license", {}).get("id") or l.get("license", {}).get("name") or l.get("expression")
                                                    for l in (c.get("licenses") or []) if isinstance(l, dict)]}
        elif "spdxVersion" in data:
            for pkg in (data.get("packages") or []):
                # SPDX packages from Syft include both real packages and (depending on catalogers)
                # file-ish entries; keep ones that have a version or a purl.
                purl = (pkg.get("externalRefs") and next((r.get("referenceLocator") for r in pkg["externalRefs"] if r.get("referenceType") == "purl"), None))
                ver = pkg.get("versionInfo")
                if not (purl or (ver and ver not in ("NOASSERTION", "", None))):
                    continue
                key = purl or f"{pkg.get('name')}@{ver}"
                if key and key not in components:
                    components[key] = {"name": pkg.get("name"), "version": ver, "type": "library", "purl": purl,
                                       "licenses": [pkg.get("licenseConcluded") or pkg.get("licenseDeclared")]}
    from collections import Counter
    by_type = dict(Counter((c.get("type") or "library") for c in components.values()))
    dump_json({"generated": now_iso(), "count": len(components), "by_type": by_type,
               "note": "Software baseline (packages/applications/OS only — file-level SBOM entries excluded).",
               "components": sorted(components.values(), key=lambda x: ((x.get("type") or ""), (x.get("name") or "").lower()))},
              sbom_dir / "components.json")
    return found, len(components)


# --------------------------------------------------------------------------- driver
PARSERS = [
    (lambda n: "codescanning-alert" in n and n.endswith(".json"), parse_codescanning_alerts, "code-scanning"),
    (lambda n: n.endswith(".sarif") or n.endswith(".sarif.json"), parse_sarif, "sarif"),
    (lambda n: "trivy" in n and n.endswith(".json"), parse_trivy, "trivy"),
    (lambda n: "grype" in n and n.endswith(".json"), parse_grype, "grype"),
    (lambda n: ("dependency-check" in n) and n.endswith(".json"), parse_dependency_check, "dependency-check"),
    (lambda n: ("zap" in n or n == "report.json") and n.endswith(".json"), parse_zap, "zap"),
    (lambda n: n.startswith("checkov") and n.endswith(".json"), parse_checkov, "checkov"),
    (lambda n: "kics" in n and n.endswith(".json"), parse_kics, "kics"),
    (lambda n: "conftest" in n and n.endswith(".json"), parse_conftest, "conftest"),
    (lambda n: "gitleaks" in n and n.endswith(".json"), parse_gitleaks, "gitleaks"),
    (lambda n: "trufflehog" in n and (n.endswith(".json") or n.endswith(".jsonl")), parse_trufflehog, "trufflehog"),
    (lambda n: n.startswith("dockle") and n.endswith(".json"), parse_dockle, "dockle"),
    (lambda n: "scorecard" in n and n.endswith(".json"), parse_scorecard, "scorecard"),
    (lambda n: "openscap" in n and n.endswith(".xml"), parse_openscap_xml, "openscap"),
    (lambda n: n.endswith(".ckl"), parse_ckl, "ckl"),
    (lambda n: "license-report" in n and n.endswith(".json"), parse_license_report, "license-report"),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, help="directory of downloaded job artifacts")
    ap.add_argument("--out", required=True, help="output evidence directory")
    ap.add_argument("--run-url", default="", help="URL of the pipeline run (for traceability)")
    a = ap.parse_args()

    root = Path(a.input)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    findings = []
    ingested = []
    skipped = []
    gates_seen = set()

    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        n = p.name.lower()
        # SBOMs handled separately; skip pure SBOM files here
        if n.endswith(".spdx.json") or n.endswith(".cdx.json"):
            continue
        for pred, fn, label in PARSERS:
            try:
                if pred(n):
                    new = fn(p, a.run_url)
                    if new is not None:
                        findings.extend(new)
                        ingested.append({"file": str(p.relative_to(root)), "parser": label, "findings": len(new)})
                        for f in new:
                            gates_seen.add(f["gate"])
                    break
            except Exception as exc:  # never let one bad file kill the aggregation
                skipped.append({"file": str(p.relative_to(root)), "error": str(exc)})
                break
        else:
            # not a recognized findings artifact (could be HTML/CSV/coverage/etc.) — ignore quietly
            pass

    # deduplicate by fingerprint, keeping the max severity / merging cve lists
    dedup = {}
    for f in findings:
        fp = f["fingerprint"]
        if fp in dedup:
            cur = dedup[fp]
            from evidence_common import SEVERITY_RANK
            if SEVERITY_RANK.get(f["severity"], 0) > SEVERITY_RANK.get(cur["severity"], 0):
                cur["severity"] = f["severity"]
            cur["cve"] = sorted(set(cur["cve"]) | set(f["cve"]))
            cur["cwe"] = sorted(set(cur["cwe"]) | set(f["cwe"]))
            cur["tags"] = sorted(set(cur["tags"]) | set(f["tags"]))
        else:
            dedup[fp] = f
    findings = list(dedup.values())

    # which gates ran (presence of artifacts from that gate's tools), even if 0 findings
    tool_dir_hints = {d.name for d in root.iterdir() if d.is_dir()}
    for d in tool_dir_hints:
        for key, gate in {"sast": "sast", "sca": "sca", "sbom": "sbom", "secrets": "secrets",
                          "iac": "iac", "license": "license", "container": "container", "dast": "dast",
                          "stig": "stig", "scorecard": "supply-chain", "build-test": "build-test"}.items():
            if key in d:
                gates_seen.add(gate)

    sboms, n_components = collect_sboms(root, out)

    dump_json(findings, out / "findings.json")
    dump_json({
        "generated": now_iso(),
        "run_url": a.run_url,
        "gates_executed": sorted(gates_seen),
        "total_findings": len(findings),
        "by_severity": {s: sum(1 for f in findings if f["severity"] == s) for s in ["critical", "high", "medium", "low", "info"]},
        "by_gate": {g: sum(1 for f in findings if f["gate"] == g) for g in sorted(gates_seen)},
        "by_tool": _count(findings, "tool"),
        "ingested_artifacts": ingested,
        "skipped_artifacts": skipped,
        "sboms": sboms,
        "sbom_component_count": n_components,
    }, out / "evidence_index.json")

    print(f"Aggregated {len(findings)} findings from {len(ingested)} artifact(s); "
          f"{len(sboms)} SBOM(s), {n_components} components. Gates seen: {sorted(gates_seen)}")
    if skipped:
        print(f"::warning::{len(skipped)} artifact(s) could not be parsed (see evidence_index.json).")


def _count(items, key):
    out = {}
    for it in items:
        out[it[key]] = out.get(it[key], 0) + 1
    return dict(sorted(out.items()))


if __name__ == "__main__":
    main()
