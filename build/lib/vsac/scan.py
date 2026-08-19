"""
vsac/scan.py — pure, cache-only evaluation. No network calls, ever.

This is the direct replacement for xbom's scan_one_package, with the
network calls surgically removed rather than patched around — per
DECISIONS.md, interleaving fetch + finding logic was the violation, so
the fix is a full separation, not a conditional skip. All network
fetching now lives exclusively in vsac.refresh; this module only reads
what refresh already wrote via vsac.cache.

Because there's no I/O left in the per-package evaluation, the
ThreadPoolExecutor from xbom's cmd_scan is gone too — it existed only to
parallelize network round-trips, which no longer happen here.

This file is orchestration only: CVE-extraction from cached OSV data,
the OUTDATED check, and cache-miss/lookup-error handling. Slopsquatting
and staleness/new-package heuristics live in vsac.slopsquat (they don't
touch the cache and don't need to live here) — this module just calls
into it and merges the results.

Finding types:
  - "CVE"            — from cached OSV data
  - "supply chain"   — OUTDATED (here) / STALE (from vsac.slopsquat)
  - "slopsquatting"  — not-found / newly-registered / sloppy-name signals,
                        from vsac.slopsquat plus the not-found check below
  - "lookup_error"   — the cached refresh recorded an OSV or registry
                        fetch failure (i.e. it WAS attempted, but failed)
  - "coverage-gap"   — no cache entry exists at all for this package.
                        Not a severity-scale finding. Excluded from any
                        aggregate/rollup score. Forces a non-zero exit
                        independent of every other finding in the scan.
                        See DECISIONS.md — this is locked, not up for
                        re-litigation as "just treat it like an error".
"""

from __future__ import annotations

from typing import Optional

from . import cache, cvss, slopsquat


def _extract_cve_findings(vulns: list) -> list[dict]:
    findings = []
    seen_cve_ids = set()

    for v in vulns:
        if not isinstance(v, dict):
            findings.append({
                "type": "lookup_error",
                "detail": "cached OSV entry was an unexpected (non-dict) shape — skipped",
            })
            continue

        aliases = v.get("aliases", [v.get("id", "?")])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), v.get("id", "?"))

        # Dedupe by CVE ID: OSV can legitimately return the same CVE
        # more than once for a single query (e.g. matched via multiple
        # affected ranges, or aliased under more than one advisory id
        # that both resolve to the same CVE). Whatever the upstream
        # cause, the same CVE for the same package/version must never
        # produce two separate findings.
        if cve_id in seen_cve_ids:
            continue
        seen_cve_ids.add(cve_id)

        severity = cvss.severity_for_vuln(v)
        fixed_ver = "see advisory"

        for affected in v.get("affected", []):
            if not isinstance(affected, dict):
                continue
            for rng in affected.get("ranges", []):
                if not isinstance(rng, dict):
                    continue
                for event in rng.get("events", []):
                    if isinstance(event, dict) and "fixed" in event:
                        fixed_ver = event["fixed"]

        findings.append({"type": "CVE", "id": cve_id, "severity": severity, "fixed": fixed_ver})
    return findings


def scan_one_package(name: str, version: Optional[str], ecosystem: str = "PyPI",
                      cache_dir=cache.DEFAULT_CACHE_DIR) -> dict:
    """
    Pure, cache-only evaluation of a single package. No network I/O.

    Returns {"name", "version", "findings": [...]}. If the package has
    never been refreshed, findings is exactly one coverage-gap finding —
    no CVE/supply-chain/slopsquatting evaluation is attempted, since
    there's nothing cached to evaluate against.
    """
    entry = cache.get_entry(name, version, ecosystem=ecosystem, cache_dir=cache_dir)

    if entry is None:
        return {
            "name": name,
            "version": version,
            "findings": [{
                "type": "coverage-gap",
                "detail": (
                    f"no cache entry for {name}=={version or 'unpinned'} — "
                    f"run 'vsac refresh' before scanning"
                ),
            }],
        }

    findings: list[dict] = []

    osv_status = entry.get("osv_status")
    if osv_status == "error":
        findings.append({
            "type": "lookup_error",
            "detail": "cached refresh recorded an OSV fetch failure for this package",
        })
    else:
        findings.extend(_extract_cve_findings(entry.get("osv_vulns") or []))

    meta = entry.get("registry_meta")
    registry_status = entry.get("registry_status")

    if registry_status == "not_found":
        label = {"npm": "npm registry", "rust": "crates.io"}.get(ecosystem, "PyPI")
        findings.append({
            "type": "slopsquatting",
            "detail": f"NOT FOUND on {label} — possible hallucinated package name",
        })
    elif registry_status == "error":
        findings.append({
            "type": "lookup_error",
            "detail": "cached refresh recorded a registry fetch failure for this package",
        })
    elif registry_status == "ok":
        if ecosystem == "PyPI" and meta and version:
            latest = meta.get("info", {}).get("version", "")
            if latest and latest != version:
                findings.append({
                    "type": "supply chain", "id": "OUTDATED",
                    "detail": f"pinned {version} — latest as of last refresh was {latest}",
                })

        findings.extend(slopsquat.evaluate(name, meta, ecosystem=ecosystem))

    return {"name": name, "version": version, "findings": findings}


def scan_packages(packages: list[tuple[str, Optional[str]]], ecosystem: str = "PyPI",
                   cache_dir=cache.DEFAULT_CACHE_DIR) -> list[dict]:
    """Pure sequential loop — no thread pool, since there's no I/O left to parallelize."""
    return [scan_one_package(name, version, ecosystem=ecosystem, cache_dir=cache_dir)
            for name, version in packages]


def has_coverage_gap(results: list[dict]) -> bool:
    return any(f["type"] == "coverage-gap" for r in results for f in r["findings"])


def exit_code_for(results: list[dict]) -> int:
    """
    Non-zero if ANY coverage-gap exists, independent of severity —
    this is deliberate per DECISIONS.md: cache incompleteness must
    surface as a build-breaking condition on its own, not be masked
    by an otherwise-clean severity scan.
    """
    if has_coverage_gap(results):
        return 1
    severity_rank = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 2}
    highest = "none"
    for r in results:
        for f in r["findings"]:
            if f["type"] == "CVE":
                sev = f.get("severity", "unknown")
                if severity_rank.get(sev, 2) > severity_rank[highest]:
                    highest = sev
    return 1 if highest in ("critical", "high") else 0