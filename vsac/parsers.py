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


class UnsupportedManifestError(Exception):
    """
    Raised when a manifest is correctly identified but its dependency
    section uses a format VSac deliberately does not parse (currently:
    Poetry's [tool.poetry.dependencies]).

    Deliberately NOT a subclass of ParseError. ParseError means "there is
    nothing to scan here" and callers (cli.py) exit 2 without attempting
    --json output, per the pre-existing usage/parse-error contract.
    UnsupportedManifestError means the opposite: VSac recognizes exactly
    what this is and is choosing not to parse it -- that's real
    information the caller should surface as a normal lookup-error
    finding through the standard --json envelope path, not a crash.
    See DECISIONS.md's manifest-format-coverage addendum.
    """


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


def _parse_pep508_dep(dep_str: str) -> Optional[tuple[str, Optional[str]]]:
    """
    Extract (name, version) from a single PEP 508 dependency-specifier
    string, e.g. "requests>=2.31,<3" or "pytest==8.0.0" or
    "foo[extra]>=1 ; python_version >= '3.11'".

    version is the exact pin only (an "==" clause) -- same convention as
    parse_requirements. A range-only spec ("requests>=2.31,<3") yields
    version=None, exactly as an unpinned requirements.txt line would.
    Environment markers (after ";") and extras ("[extra]") are stripped
    since neither affects which package/version is actually installed.
    """
    dep_str = dep_str.split(";", 1)[0].strip()
    dep_str = re.sub(r"\[[^\]]*\]", "", dep_str)  # drop extras, e.g. "foo[extra]" -> "foo"

    m = re.match(r"^([A-Za-z0-9_.\-]+)", dep_str)
    if not m:
        return None
    name = m.group(1).lower()

    pin = re.search(r"==\s*([A-Za-z0-9_.\-]+)", dep_str[len(m.group(1)):])
    version = pin.group(1) if pin else None
    return (name, version)


def parse_pyproject(project_path) -> list[tuple[str, Optional[str]]]:
    """
    Return a list of (name, version) tuples from a PEP 621
    [project.dependencies] array.

    Scope, locked (see DECISIONS.md manifest-format-coverage addendum):
      - PEP 621 [project.dependencies]: parsed. This is a fixed, bounded
        spec -- an array of PEP 508 strings -- not an open-ended format.
      - Poetry's [tool.poetry.dependencies]: recognized but NOT parsed.
        Its version-constraint syntax (^1.2.3, ~1.2) is not PEP
        508-compatible; parsing it correctly is separate scope.
        Raises UnsupportedManifestError rather than silently returning
        [] or crashing -- "declined" is a stated position, not silence.
      - Anything else (no [project.dependencies], no [tool.poetry]):
        raises ParseError -- there is nothing here VSac recognizes at
        all, same category as a missing/unreadable requirements.txt.

    [project.optional-dependencies] is deliberately NOT parsed in this
    pass -- flagged as a natural, separate follow-up rather than folded
    in opportunistically (same DECISIONS.md-style caution against
    scope creep that applies to Poetry).
    """
    try:
        import tomllib
    except ImportError:
        tomllib = None

    path = Path(project_path)
    pyproject_path = path / "pyproject.toml" if path.is_dir() else path

    if not pyproject_path.exists():
        raise ParseError(f"File not found: {pyproject_path}")

    if tomllib is None:
        raise ParseError(
            f"Cannot parse {pyproject_path}: Python < 3.11 has no built-in TOML parser "
            f"(tomllib), and VSac does not add a third-party TOML dependency for this."
        )

    try:
        raw_text = pyproject_path.read_text(encoding="utf-8")
    except (OSError, PermissionError) as e:
        raise ParseError(f"Could not read {pyproject_path}: {e}")

    try:
        data = tomllib.loads(raw_text)
    except tomllib.TOMLDecodeError as e:
        raise ParseError(f"Could not parse {pyproject_path} as TOML: {e}")

    project = data.get("project", {})
    deps = project.get("dependencies")

    if deps:
        packages = []
        for dep in deps:
            if not isinstance(dep, str):
                continue
            parsed = _parse_pep508_dep(dep)
            if parsed:
                packages.append(parsed)
        return packages

    if "poetry" in data.get("tool", {}):
        raise UnsupportedManifestError(
            f"{pyproject_path} declares dependencies via [tool.poetry.dependencies] "
            f"(Poetry), which VSac recognizes but does not parse -- Poetry's "
            f"version-constraint syntax (^1.2.3, ~1.2) is not PEP 508-compatible. "
            f"This is a declined manifest format, not an unsupported one; see "
            f"DECISIONS.md. Convert to PEP 621 [project.dependencies], or run "
            f"'vsac scan --ecosystem PyPI requirements.txt' against an exported "
            f"requirements file instead."
        )

    raise ParseError(
        f"{pyproject_path} has neither [project.dependencies] (PEP 621) nor "
        f"[tool.poetry.dependencies] (Poetry) -- VSac found nothing recognizable to scan."
    )


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