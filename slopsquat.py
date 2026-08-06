"""
vsac/slopsquat.py — direct port of xbom's slopsquatting heuristic.

This is a local, no-network heuristic: name-pattern matching plus
registry-metadata age checks. It never touches the cache directly and
never needs refresh timestamps beyond what's already sitting in a
registry_meta blob — the caller (scan.py) hands it whatever it already
has, and it hands back yes/no + detail strings.

Ported verbatim from xbom's main.py: SLOPPY_PATTERNS, its npm variant,
has_sloppy_name(), and the staleness / newly-registered-package
thresholds. Do not fold cache-eval logic into this file — its value is
being a diffable, direct port. If xbom's heuristic changes upstream,
this file is where that diff lands, not scan.py.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

STALE_YEARS = 2
NEW_PACKAGE_DAYS = 90

SLOPPY_PATTERNS = [
    r"^python-[\w]+-[\w]+$",
    r"^[\w]+-helper-[\w]+$",
    r"^[\w]+-client-[\w]+$",
    r"^[\w]+-api-[\w]+$",
    r"^[\w]+-utils-[\w]+$",
    r"^[\w]+-tools-[\w]+$",
    r"^[\w]+-wrapper-[\w]+$",
]

SLOPPY_PATTERNS_NPM = [
    r"^node-[\w-]+-helper$",
    r"^[\w-]+-utils-[\w-]+$",
    r"^[\w-]+-client-wrapper$",
    r"^[\w-]+-api-tools$",
]


def has_sloppy_name(name: str, ecosystem: str = "PyPI") -> bool:
    patterns = SLOPPY_PATTERNS_NPM if ecosystem == "npm" else SLOPPY_PATTERNS
    return any(re.match(p, name, re.IGNORECASE) for p in patterns)


def days_since(date_str: Optional[str]) -> Optional[int]:
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def registry_dates(meta: Optional[dict], ecosystem: str) -> list[str]:
    """
    Extract every known publish/release timestamp for a package from its
    cached registry metadata blob, ecosystem-specific shape and all.
    """
    if not meta:
        return []
    if ecosystem == "npm":
        time_map = meta.get("time", {})
        return [v for k, v in time_map.items() if k not in ("created", "modified")]
    if ecosystem == "rust":
        versions = meta.get("versions", [])
        return [v.get("created_at") for v in versions if v.get("created_at")]
    # PyPI
    return [
        f.get("upload_time")
        for rel_files in meta.get("releases", {}).values()
        for f in rel_files
        if f.get("upload_time")
    ]


def evaluate(name: str, meta: Optional[dict], ecosystem: str = "PyPI") -> list[dict]:
    """
    Run the full slopsquatting heuristic against cached registry
    metadata for one package. Returns a list of finding dicts (type
    "slopsquatting" or "supply chain"), possibly empty.

    Does NOT check "not found on registry" — that's a registry_status
    check the caller (scan.py) already has and should surface itself,
    since it isn't specific to slopsquatting.
    """
    findings: list[dict] = []

    all_dates = registry_dates(meta, ecosystem)
    if all_dates:
        age = days_since(max(all_dates))
        if age and age > STALE_YEARS * 365:
            findings.append({
                "type": "supply chain", "id": "STALE",
                "detail": f"last updated {age // 365} years ago (as of last refresh)",
            })

        age_since_first = days_since(min(all_dates))
        if age_since_first is not None and age_since_first < NEW_PACKAGE_DAYS:
            findings.append({
                "type": "slopsquatting",
                "detail": f"registered only {age_since_first} days ago — newly created package",
            })

    if has_sloppy_name(name, ecosystem=ecosystem):
        findings.append({
            "type": "slopsquatting",
            "detail": "name matches a pattern commonly seen in AI-hallucinated packages",
        })

    return findings