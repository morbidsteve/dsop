"""NTIA "Minimum Elements for an SBOM" (July 2021) structural validator.

Checks a CycloneDX or SPDX JSON document for the baseline data fields (Supplier, Component name,
Version, Other unique identifiers, Dependency relationships, Author of SBOM data, Timestamp) and
flags "known unknowns". This is the same kind of check the pipeline runs in
scripts/evidence_common.py --validate-sbom; exposing it as an API endpoint makes the demo workload
do something genuinely useful and on-theme.
"""
from __future__ import annotations

from typing import Any


def _cdx_components(sbom: dict) -> list[dict]:
    comps = list(sbom.get("components") or [])
    out = list(comps)
    for c in comps:
        out.extend(c.get("components") or [])
    return out


def detect_format(sbom: Any) -> str:
    if not isinstance(sbom, dict):
        return "unknown"
    if sbom.get("bomFormat") == "CycloneDX" or "specVersion" in sbom:
        return "CycloneDX"
    if "spdxVersion" in sbom:
        return "SPDX"
    return "unknown"


def validate(sbom: Any) -> dict:
    """Return a report: {format, valid, summary, issues:[...], component_count}."""
    fmt = detect_format(sbom)
    issues: list[str] = []
    if fmt == "unknown":
        return {"format": "unknown", "valid": False, "component_count": 0,
                "issues": ["Document is not a recognized SBOM (expected CycloneDX or SPDX JSON)."],
                "summary": "Not an SBOM."}

    if fmt == "CycloneDX":
        md = sbom.get("metadata") or {}
        if not md.get("timestamp"):
            issues.append("metadata.timestamp missing (NTIA: Timestamp).")
        if not (md.get("authors") or md.get("tools")):
            issues.append("metadata.authors / metadata.tools missing (NTIA: Author of SBOM Data).")
        comps = _cdx_components(sbom)
        if not comps:
            issues.append("No components listed.")
        for i, c in enumerate(comps):
            tag = c.get("name") or f"component[{i}]"
            if not c.get("name"):
                issues.append(f"{tag}: missing 'name' (NTIA: Component Name).")
            if not c.get("version"):
                issues.append(f"{tag}: missing 'version' (NTIA: Version of the Component).")
            if not (c.get("purl") or c.get("cpe") or c.get("bom-ref")):
                issues.append(f"{tag}: missing a unique identifier — purl/cpe (NTIA: Other Unique Identifiers).")
            if not (c.get("supplier") or c.get("publisher") or c.get("author")):
                issues.append(f"{tag}: missing supplier/publisher/author (NTIA: Supplier Name).")
        if not sbom.get("dependencies"):
            issues.append("No 'dependencies' graph (NTIA: Dependency Relationship / Depth).")
        n_components = len(comps)
    else:  # SPDX
        ci = sbom.get("creationInfo") or {}
        if not ci.get("created"):
            issues.append("creationInfo.created missing (NTIA: Timestamp).")
        if not ci.get("creators"):
            issues.append("creationInfo.creators missing (NTIA: Author of SBOM Data).")
        pkgs = sbom.get("packages") or []
        if not pkgs:
            issues.append("No packages listed.")
        for i, p in enumerate(pkgs):
            tag = p.get("name") or f"package[{i}]"
            if not p.get("name"):
                issues.append(f"{tag}: missing 'name' (NTIA: Component Name).")
            if not p.get("versionInfo") or p.get("versionInfo") == "NOASSERTION":
                issues.append(f"{tag}: missing versionInfo (NTIA: Version of the Component).")
            refs = [r.get("referenceType") for r in (p.get("externalRefs") or [])]
            if "purl" not in refs and not p.get("packageVerificationCode"):
                issues.append(f"{tag}: missing a unique identifier — purl externalRef (NTIA: Other Unique Identifiers).")
            if not p.get("supplier") or p.get("supplier") == "NOASSERTION":
                issues.append(f"{tag}: missing supplier (NTIA: Supplier Name).")
        if not sbom.get("relationships"):
            issues.append("No 'relationships' (NTIA: Dependency Relationship / Depth).")
        n_components = len(pkgs)

    # Cap the issue list so a bad SBOM doesn't return megabytes.
    capped = issues[:200]
    valid = len(issues) == 0
    return {
        "format": fmt,
        "valid": valid,
        "component_count": n_components,
        "issue_count": len(issues),
        "issues": capped,
        "truncated": len(issues) > len(capped),
        "summary": ("Meets the NTIA SBOM minimum-element checklist (structural check)." if valid
                    else f"{len(issues)} NTIA minimum-element gap(s) found."),
        "ntia_reference": "NTIA, 'The Minimum Elements For a Software Bill of Materials (SBOM)', July 2021.",
    }
