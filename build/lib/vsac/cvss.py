"""
vsac/cvss.py — CVSS v3.0/v3.1 base-score calculator, stdlib-only.

Root cause of the "every CVE is INFO" bug: OSV's `severity[].score` field
is a raw CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/
I:N/A:H"), not a precomputed qualitative word. The previous code did
`"HIGH" in score.upper()` on that vector string, which never matches
(the vector has no such substring), so severity silently fell through
to "unknown" -> INFO for every real CVE. Confirmed against the actual
OSV API schema and OSV maintainers' own statement that the API does not
provide a precomputed score ("Our API doesn't provide the calculated
score at the moment" -- google/osv.dev#2643).

This module implements the standard CVSS v3.1 base-score formula
(FIRST.org spec) to turn a vector string into a real qualitative
severity, with no new dependency. GHSA-sourced entries sometimes carry
a plain-word severity under `database_specific.severity` instead of/in
addition to a vector -- that's checked first since it's cheaper and
already authoritative when present.
"""

from __future__ import annotations

import math
from typing import Optional

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}

_QUALITATIVE_WORDS = {"CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "NONE"}
_WORD_TO_SEVERITY = {
    "CRITICAL": "critical", "HIGH": "high",
    "MEDIUM": "medium", "MODERATE": "medium",
    "LOW": "low", "NONE": "unknown",
}


def _roundup(value: float) -> float:
    """CVSS spec's specific round-up-to-1-decimal rule, not plain round()."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (math.floor(int_value / 10000) + 1) / 10.0


def _parse_vector(vector: str) -> Optional[dict]:
    if not vector.startswith("CVSS:3"):
        return None
    parts = {}
    for segment in vector.split("/")[1:]:
        if ":" not in segment:
            continue
        k, v = segment.split(":", 1)
        parts[k] = v
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(parts):
        return None
    return parts


def base_score(vector: str) -> Optional[float]:
    """Return the CVSS v3.x base score (0.0-10.0) for a vector string, or None if unparseable."""
    m = _parse_vector(vector)
    if m is None:
        return None

    try:
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        ui = _UI[m["UI"]]
        scope_changed = m["S"] == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope_changed:
        return min(_roundup(1.08 * (impact + exploitability)), 10.0)
    return min(_roundup(impact + exploitability), 10.0)


def score_to_severity(score: float) -> str:
    """Standard CVSS v3.x qualitative severity rating bucketing."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def severity_for_vuln(vuln: dict) -> str:
    """
    Determine the qualitative severity for one raw OSV vuln entry.
    Checks, in order:
      1. database_specific.severity (GHSA plain-word convention, when present)
      2. Highest computed base_score across all CVSS_V2/V3/V4 vector entries
      3. "unknown" if neither is present/parseable
    """
    db_specific = vuln.get("database_specific", {})
    if isinstance(db_specific, dict):
        word = str(db_specific.get("severity", "")).upper()
        if word in _QUALITATIVE_WORDS:
            return _WORD_TO_SEVERITY[word]

    best_score = None
    for sev_entry in vuln.get("severity", []):
        if not isinstance(sev_entry, dict):
            continue
        vector = sev_entry.get("score", "")
        score = base_score(vector)
        if score is not None and (best_score is None or score > best_score):
            best_score = score

    if best_score is not None:
        return score_to_severity(best_score)

    return "unknown"