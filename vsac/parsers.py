"""
vsac/parsers.py — direct port of xbom's dependency-file parsers.

parse_requirements, parse_npm_project, parse_rust_project (plus the
looks_like_xbom_report guard parse_requirements relies on) are ported
verbatim. None of these touch the network or the cache — they only read
project files off disk and return (name, version) tuples — so, same
rationale as slopsquat.py, they get their own file rather than living
inside scan.py or refresh.py.

One change from the xbom original: parse_requirements no longer calls
sys.exit() on a bad path. xbom was a single CLI script where exiting
straight from a parser was fine; VSac's scan.py may call this as a
library function from other orchestration (e.g. cmd_audit), so parse
errors are raised as ParseError instead and left for the caller to
handle (print + exit, or otherwise) — this is the one deliberate
deviation from "ports directly without changes," and it's a control-flow
change only, not a change to parsing logic or heuristics themselves.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional


class ParseError(Exception):
    """Raised on an unreadable or misidentified dependency file."""


# Signatures that only ever appear in xbom's own printed/exported output,
# never in a genuine requirements.txt. Used by looks_like_xbom_report() to
# guard against a report file being accidentally re-fed into parse_requirements.
XBOM_REPORT_SIGNATURES = [
    "XBOM — SOFTWARE BILL OF MATERIALS",
    "XBOM — SECURITY SCAN",
    "querying OSV and PyPI for",
    "scanning ",  # "scanning N packages (CVE, supply chain, slopsquatting)..."
    "name corrections applied before scanning",
]


def looks_like_xbom_report(raw_text: str) -> bool:
    """
    Return True if raw_text looks like an xbom-generated report rather
    than a genuine requirements file. Reports are for reading, not for
    re-scanning — feeding one back into parse_requirements produces
    garbage entries (e.g. a bogus 'xbom' component) extracted from
    headers and labels that loosely match the package-name pattern.
    """
    for signature in XBOM_REPORT_SIGNATURES:
        if signature in raw_text:
            return True

    # A long run of "=" or "-" characters is xbom's section-separator
    # style (e.g. "=" * 60), which never appears in a requirements file.
    if re.search(r"[=\-]{20,}", raw_text):
        return True

    return False


def parse_requirements(req_file) -> list[tuple[str, Optional[str]]]:
    """
    Read a requirements file and return a list of (name, version) tuples.
    Skips comments, blank lines, and entries without pinned versions.
    """
    packages = []
    req_path = Path(req_file)

    if req_path.is_dir():
        raise ParseError(
            f"Expected a requirements.txt file, got a directory: {req_file} "
            f"(tip: use 'vsac audit {req_file}' to generate one automatically)"
        )

    try:
        raw_text = req_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ParseError(
            f"File not found: {req_file} "
            f"(tip: use 'vsac audit /path/to/project' to generate one automatically)"
        )
    except PermissionError:
        raise ParseError(
            f"Permission denied reading: {req_file} "
            f"(if this is a project folder, use 'vsac audit {req_file}' instead)"
        )

    if looks_like_xbom_report(raw_text):
        raise ParseError(
            f"This looks like an xbom/vsac-generated report, not a requirements file: {req_file} "
            f"(point 'scan' at the actual requirements.txt, not a file in reports/)"
        )

    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)[=!<>~]+([A-Za-z0-9_.\-]+)", line)
        if match:
            packages.append((match.group(1).lower(), match.group(2)))
        else:
            name = re.match(r"^([A-Za-z0-9_.\-]+)", line)
            if name:
                packages.append((name.group(1).lower(), None))

    return packages


def parse_npm_project(project_path) -> list[tuple[str, Optional[str]]]:
    """
    Return a list of (name, version) tuples for a project's npm
    dependencies. Prefers package-lock.json (fully resolved versions);
    falls back to package.json (version ranges — less precise for a CVE
    scan, since the range doesn't tell you which exact version is
    actually installed, but better than nothing when no lockfile exists).

    Returns [] if neither file is present — the caller decides whether
    that means "not an npm project" or "no dependencies."
    """
    project_root = Path(project_path)
    lock_file = project_root / "package-lock.json"
    pkg_file = project_root / "package.json"

    if lock_file.exists():
        try:
            data = json.loads(lock_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = None

        if data:
            packages = []
            # npm lockfile v2/v3 format: flat "packages" map keyed by
            # node_modules path, e.g. "node_modules/lodash".
            if "packages" in data:
                for pkg_path, info in data["packages"].items():
                    if not pkg_path or "node_modules/" not in pkg_path:
                        continue
                    name = pkg_path.split("node_modules/")[-1]
                    version = info.get("version")
                    if name and version:
                        packages.append((name, version))
            # npm lockfile v1 format: nested "dependencies" map.
            elif "dependencies" in data:
                for name, info in data["dependencies"].items():
                    version = info.get("version")
                    if version:
                        packages.append((name, version))

            if packages:
                # de-duplicate, keeping first version seen per name
                seen = {}
                for name, version in packages:
                    seen.setdefault(name, version)
                return sorted(seen.items())

    if pkg_file.exists():
        try:
            data = json.loads(pkg_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []

        packages = {}
        for section in ("dependencies", "devDependencies"):
            for name, range_spec in data.get(section, {}).items():
                # Strip range operators (^, ~, >=, etc.) — not a resolved
                # version, just the loosest usable hint when no lockfile
                # is available to pin an exact one.
                cleaned = re.sub(r"^[\^~>=<\s]+", "", range_spec)
                packages[name] = cleaned

        return sorted(packages.items())

    return []


def parse_rust_project(project_path) -> list[tuple[str, Optional[str]]]:
    """
    Return a list of (name, version) tuples for a project's Rust/Cargo
    dependencies. Prefers Cargo.lock (fully resolved versions); falls
    back to Cargo.toml (version ranges, same caveat as npm's package.json
    fallback — a real range if no lockfile exists yet).

    Returns [] if neither file is present.
    """
    try:
        import tomllib
    except ImportError:
        # Python < 3.11 has no built-in TOML parser and we don't want to
        # force a third-party dependency just for this fallback path.
        tomllib = None

    project_root = Path(project_path)
    lock_file = project_root / "Cargo.lock"
    toml_file = project_root / "Cargo.toml"

    if lock_file.exists() and tomllib:
        try:
            data = tomllib.loads(lock_file.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            data = None

        if data:
            packages = {}
            for pkg in data.get("package", []):
                name = pkg.get("name")
                version = pkg.get("version")
                if name and version:
                    packages.setdefault(name, version)
            if packages:
                return sorted(packages.items())

    if toml_file.exists() and tomllib:
        try:
            data = tomllib.loads(toml_file.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            return []

        packages = {}
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, spec in data.get(section, {}).items():
                if isinstance(spec, str):
                    version = re.sub(r"^[\^~>=<\s]+", "", spec)
                elif isinstance(spec, dict):
                    version = spec.get("version", "")
                    version = re.sub(r"^[\^~>=<\s]+", "", version) if version else "unpinned"
                else:
                    version = "unpinned"
                packages[name] = version

        return sorted(packages.items())

    return []