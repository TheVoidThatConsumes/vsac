"""
vsac/schema.py — translates scan.py's internal finding shape into a
Gossamer finding-envelope-conformant report (schema/finding-envelope.schema.json).

scan.py's output is intentionally NOT envelope-shaped — it's a plain
{"name", "version", "findings": [...]} per package, with internal
finding "type" tags (CVE, supply chain, slopsquatting, lookup_error,
coverage-gap) that don't match the envelope's required
id/severity/category/title/location shape. This module is the only
place that boundary gets crossed.

The four advisory category slugs below are registered in the controller's
categories.json (dependency-outdated, dependency-stale, lookup-error,
coverage-gap) -- locked, see DECISIONS.md.

SEVERITY ON ADVISORY FINDINGS: known-vulnerability derives its severity
straight from cached OSV data. The other four categories have no CVE
data to derive severity from, so they use the locked default-severity
table below (see DECISIONS.md for rationale on each choice):

    slopsquatting          HIGH    (active-attack pattern, not hygiene)
    dependency-outdated    LOW     (fixed version exists, no active exploit)
    dependency-stale       INFO    (hygiene signal, not security)
    lookup-error           MEDIUM  (blocks real assessment, shouldn't be noise)
    coverage-gap           INFO    (explicitly excluded from severity scale)

Do not let a future refactor read severity="INFO" on coverage-gap as
"this is a low-priority finding" -- it means "this finding doesn't
participate in the severity scale at all," per DECISIONS.md.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

SCHEMA_VERSION = "1.0"
TOOL_NAME = "vsac"
ID_PREFIX = "VS"

# category slug for each internal finding "type" + optional "id" subtype.
_CATEGORY_MAP = {
    ("CVE", None): "known-vulnerability",
    ("supply chain", "OUTDATED"): "dependency-outdated",
    ("supply chain", "STALE"): "dependency-stale",
    ("slopsquatting", None): "slopsquatting",
    ("lookup_error", None): "lookup-error",
    ("coverage-gap", None): "coverage-gap",
}

# short code used in the id's middle segment, e.g. VS-CVE-001
_ID_CODE_MAP = {
    ("CVE", None): "CVE",
    ("supply chain", "OUTDATED"): "OUTDATED",
    ("supply chain", "STALE"): "STALE",
    ("slopsquatting", None): "SLOP",
    ("lookup_error", None): "LOOKUP",
    ("coverage-gap", None): "GAP",
}

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "unknown": "INFO",
}

# Locked default-severity rule for the four advisory categories (no CVE
# data to derive severity from). known-vulnerability is excluded here —
# its severity comes straight from cached OSV data, handled separately
# in _severity_for(). This table is the citable source of truth; see
# DECISIONS.md for the rationale behind each choice.
_ADVISORY_SEVERITY = {
    "slopsquatting": "HIGH",
    "dependency-outdated": "LOW",
    "dependency-stale": "INFO",
    "lookup-error": "MEDIUM",
    "coverage-gap": "INFO",
}


def _category_for(finding: dict) -> str:
    key = (finding["type"], finding.get("id"))
    if key not in _CATEGORY_MAP:
        key = (finding["type"], None)
    return _CATEGORY_MAP[key]


def _id_code_for(finding: dict) -> str:
    key = (finding["type"], finding.get("id"))
    if key not in _ID_CODE_MAP:
        key = (finding["type"], None)
    return _ID_CODE_MAP[key]


def _severity_for(finding: dict) -> str:
    """
    coverage-gap is not on the severity scale at all per DECISIONS.md --
    it gets INFO purely to satisfy the schema's required field, and
    consuming code must key exclusion logic off the envelope's
    non_scored flag (set in to_findings), never off this value.
    lookup-error similarly isn't a vulnerability finding, but per the
    locked severity-default table it gets a real severity (MEDIUM)
    rather than being INFO-only, since it blocks a real assessment and
    shouldn't be ignorable as pure noise.
    """
    if finding["type"] == "CVE":
        return _SEVERITY_MAP.get(finding.get("severity", "unknown"), "INFO")
    category = _category_for(finding)
    return _ADVISORY_SEVERITY.get(category, "INFO")


def _is_non_scored(finding: dict) -> bool:
    """True for findings that must not participate in the severity gate.

    coverage-gap: the package was never evaluated at all (no cache
    entry). Scoring it as INFO would let an unevaluated repo pass the
    gate -- fail closed instead, exactly like the controller's
    gate_passed() non_scored rule (see DECISIONS.md).

    lookup_error + declined_manifest: the manifest was skipped by
    policy (unsupported type), so the package was never assessed. A
    lookup_error from a real refresh failure stays scored (MEDIUM) --
    that's a cache-health warning about a package we DID assess.
    """
    if finding["type"] == "coverage-gap":
        return True
    if finding["type"] == "lookup_error":
        return bool(finding.get("declined_manifest"))
    return False


def _title_for(finding: dict, name: str, version: Optional[str]) -> str:
    pkg = f"{name}=={version}" if version else name
    if finding["type"] == "CVE":
        return f"{finding.get('id', 'CVE')} in {pkg}"
    if finding["type"] == "supply chain":
        sub = finding.get("id", "")
        if sub == "OUTDATED":
            return f"{pkg} is outdated"
        if sub == "STALE":
            return f"{pkg} has not been updated in over 2 years"
        return f"Supply-chain signal for {pkg}"
    if finding["type"] == "slopsquatting":
        return f"Possible slopsquatting: {pkg}"
    if finding["type"] == "lookup_error":
        return f"Lookup failed for {pkg} during last refresh"
    if finding["type"] == "coverage-gap":
        return f"{pkg} missing from local cache"
    return f"Finding for {pkg}"


def _location_for(name: str, version: Optional[str], ecosystem: str) -> str:
    """
    Opaque per finding-envelope.schema.json -- vsac's convention is
    "<ecosystem>:<name>@<version-or-unpinned>". Consumers must never
    parse this; it's for equality comparison (history/identity tracking)
    only, per the schema's own description field.

    NOTE: this does not yet include the originating requirements
    file/line -- parsers.py returns (name, version) tuples without
    provenance. If per-line location precision is wanted later, that's
    a parsers.py change (carry the source file alongside each tuple),
    not a schema.py change.
    """
    return f"{ecosystem}:{name}@{version if version else 'unpinned'}"


def to_findings(scan_results: list[dict], ecosystem: str = "PyPI") -> list[dict]:
    """
    Flatten scan.py's [{"name","version","findings":[...]}, ...] output
    into a flat list of envelope-conformant finding dicts, assigning
    sequential, stable-within-this-report ids per finding-type code
    (VS-CVE-001, VS-CVE-002, VS-GAP-001, ...).
    """
    counters: dict[str, int] = {}
    out: list[dict] = []

    for result in scan_results:
        name, version = result["name"], result["version"]
        for f in result["findings"]:
            code = _id_code_for(f)
            counters[code] = counters.get(code, 0) + 1
            seq = str(counters[code]).zfill(3)

            envelope_finding = {
                "id": f"{ID_PREFIX}-{code}-{seq}",
                "severity": _severity_for(f),
                "category": _category_for(f),
                "title": _title_for(f, name, version),
                "description": f.get("detail", ""),
                "location": _location_for(name, version, ecosystem),
            }
            if _is_non_scored(f):
                envelope_finding["non_scored"] = True
            out.append(envelope_finding)

    return out


def summarize(findings: list[dict]) -> dict:
    counts = {"total": len(findings), "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def build_report(scan_results: list[dict], repo: str, ecosystem: str = "PyPI",
                  baseline_commit: Optional[str] = None) -> dict:
    """
    The single entry point: scan.py's raw per-package results in,
    a finding-envelope.schema.json-conformant dict out.
    """
    findings = to_findings(scan_results, ecosystem=ecosystem)

    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo": repo,
        "findings": findings,
        "summary": summarize(findings),
    }
    if baseline_commit:
        report["baseline_commit"] = baseline_commit

    return report