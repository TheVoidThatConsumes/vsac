"""
vsac/cli.py — CLI wiring for `vsac refresh` and `vsac scan`.

Ties together the layer split: refresh.py (network, cache-writer) ->
scan.py (pure cache-eval) -> schema.py (envelope translation) -> stdout
+ process exit code. This file owns none of that logic itself, only
argument parsing, ecosystem/package-file detection, and output/exit
plumbing.

Exit codes (checked in this order):
  2 - usage/parse error (bad file, bad args) - argparse/parsers raise
  1 - coverage-gap present, OR a CRITICAL/HIGH severity finding present
  0 - clean scan (only LOW/MEDIUM/INFO findings, no coverage-gap)

`vsac scan` never touches the network -- this file does not import
`refresh` inside the scan path, only inside the refresh path, so an
accidental network call from `scan` isn't just a style violation, it's
structurally absent from the code that runs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from . import cache, parsers, scan, schema

_ECOSYSTEM_FILES = {
    "PyPI": ("requirements.txt",),
    "npm": ("package-lock.json", "package.json"),
    "rust": ("Cargo.lock", "Cargo.toml"),
}


def _detect_packages(target: str, ecosystem: Optional[str]) -> tuple[list[tuple[str, Optional[str]]], str]:
    """
    Resolve (packages, ecosystem) from a target path. If ecosystem isn't
    given explicitly, infer it from what's at the target path -- a
    requirements.txt-shaped file implies PyPI, a directory containing
    npm/cargo manifests implies those ecosystems.
    """
    path = Path(target)

    if ecosystem:
        if ecosystem == "PyPI":
            return parsers.parse_requirements(path), "PyPI"
        if ecosystem == "npm":
            return parsers.parse_npm_project(path), "npm"
        if ecosystem == "rust":
            return parsers.parse_rust_project(path), "rust"
        raise parsers.ParseError(f"Unknown ecosystem: {ecosystem}")

    if path.is_file():
        return parsers.parse_requirements(path), "PyPI"

    if path.is_dir():
        if (path / "package-lock.json").exists() or (path / "package.json").exists():
            return parsers.parse_npm_project(path), "npm"
        if (path / "Cargo.lock").exists() or (path / "Cargo.toml").exists():
            return parsers.parse_rust_project(path), "rust"
        req = path / "requirements.txt"
        if req.exists():
            return parsers.parse_requirements(req), "PyPI"
        pyproject = path / "pyproject.toml"
        if pyproject.exists():
            # May raise parsers.UnsupportedManifestError (Poetry-style) --
            # deliberately NOT caught here. cmd_scan/cmd_refresh handle it
            # differently from ParseError: ParseError below means "nothing
            # recognized at all," UnsupportedManifestError means "VSac
            # knows exactly what this is and is declining to parse it,"
            # which routes through the --json envelope, not a bare exit 2.
            return parsers.parse_pyproject(path), "PyPI"
        raise parsers.ParseError(
            f"No recognized dependency file found under {target} "
            f"(looked for requirements.txt, pyproject.toml, package-lock.json/package.json, "
            f"Cargo.lock/Cargo.toml). Use --ecosystem to force one."
        )

    raise parsers.ParseError(f"Path not found: {target}")


def cmd_refresh(args: argparse.Namespace) -> int:
    from . import refresh  # imported only here -- refresh is the one path allowed to hit the network

    try:
        packages, ecosystem = _detect_packages(args.target, args.ecosystem)
    except parsers.UnsupportedManifestError as e:
        # refresh has no --json envelope contract to honor (unlike scan) --
        # it's a network op with nothing to fetch, so this stays a plain
        # usage-style failure. Not the case this fix targets; see cmd_scan.
        print(f"[!] {e}", file=sys.stderr)
        return 2
    except parsers.ParseError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    if not packages:
        print(f"[!] No packages found in {args.target}", file=sys.stderr)
        return 2

    cache_dir = Path(args.cache_dir) if args.cache_dir else cache.DEFAULT_CACHE_DIR
    print(f"  refreshing {len(packages)} {ecosystem} package(s) -> {cache_dir}")

    result = refresh.refresh_packages(packages, ecosystem=ecosystem, cache_dir=cache_dir)

    print(f"  refreshed: {result['refreshed']}")
    if result["osv_errors"] or result["registry_errors"]:
        print(
            f"  [!] {result['osv_errors']} OSV fetch error(s), "
            f"{result['registry_errors']} registry fetch error(s) -- "
            f"recorded in cache, will surface as lookup-error findings on scan",
            file=sys.stderr,
        )

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        packages, ecosystem = _detect_packages(args.target, args.ecosystem)
    except parsers.UnsupportedManifestError as e:
        return _emit_unsupported_manifest(args, e)
    except parsers.ParseError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    if not packages:
        print(f"[!] No packages found in {args.target}", file=sys.stderr)
        return 2

    cache_dir = Path(args.cache_dir) if args.cache_dir else cache.DEFAULT_CACHE_DIR

    results = scan.scan_packages(packages, ecosystem=ecosystem, cache_dir=cache_dir)
    report = schema.build_report(results, repo=str(Path(args.target).resolve()), ecosystem=ecosystem)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)

    if scan.has_coverage_gap(results):
        if not args.json:
            gap_count = sum(1 for r in results for f in r["findings"] if f["type"] == "coverage-gap")
            print(
                f"\n[!] {gap_count} coverage-gap finding(s) present "
                f"-- run 'vsac refresh {args.target}' to populate the cache. Exiting non-zero (fail-closed).",
                file=sys.stderr,
            )
        return 1

    if report["summary"]["CRITICAL"] or report["summary"]["HIGH"]:
        return 1

    return 0


def _emit_unsupported_manifest(args: argparse.Namespace, err: "parsers.UnsupportedManifestError") -> int:
    """
    Handle a recognized-but-declined manifest (currently: Poetry-style
    pyproject.toml) through the normal --json envelope path instead of a
    bare exit 2. Per DECISIONS.md's manifest-format-coverage addendum:
    this is a lookup-error (MEDIUM), not a coverage-gap -- coverage-gap's
    locked definition is specifically "package not in cache," a
    cache-completeness concept, and reusing it here would blur that
    category's meaning. There is exactly one synthetic finding, scoped
    to the manifest itself rather than any individual package, since no
    packages were ever extracted to scan.

    Exit is non-zero (1) regardless of --gate/severity policy, mirroring
    coverage-gap's "the scan could not meaningfully run" treatment even
    though the category is different -- an unscanned repo must never
    report a clean/zero exit.

    The declined_manifest marker is what distinguishes this synthetic
    finding from a real refresh-failure lookup_error in schema.py: it
    makes the finding non_scored (fail-closed in the controller's gate),
    because the manifest was refused by policy and no real assessment
    happened -- unlike a network lookup error, which is scored MEDIUM.
    """
    target_label = str(Path(args.target).resolve())
    synthetic_result = {
        "name": Path(args.target).name or args.target,
        "version": None,
        "findings": [{"type": "lookup_error", "detail": str(err), "declined_manifest": True}],
    }
    report = schema.build_report([synthetic_result], repo=target_label, ecosystem="PyPI")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)
        print(
            f"\n[!] Manifest recognized but not parseable by VSac (see finding above) -- "
            f"exiting non-zero (fail-closed): this repo was not actually scanned.",
            file=sys.stderr,
        )

    return 1


def _print_human(report: dict) -> None:
    print(f"vsac scan — {report['repo']}")
    print(f"  {report['summary']['total']} finding(s): "
          f"{report['summary']['CRITICAL']} critical, {report['summary']['HIGH']} high, "
          f"{report['summary']['MEDIUM']} medium, {report['summary']['LOW']} low, "
          f"{report['summary']['INFO']} info")
    print()
    for f in report["findings"]:
        print(f"  [{f['severity']:>8}] {f['id']}  {f['title']}")
        if f.get("description"):
            print(f"             {f['description']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vsac", description="Venom-Sac — Gossamer Suite dependency risk scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("target", nargs="?", default=".",
                         help="requirements.txt, package.json/Cargo.toml dir, or project dir (default: current directory)")
    common.add_argument("--ecosystem", choices=["PyPI", "npm", "rust"], default=None,
                         help="Force ecosystem instead of auto-detecting from target")
    common.add_argument("--cache-dir", default=None, help="Override cache directory")

    p_refresh = sub.add_parser("refresh", parents=[common], help="Fetch OSV + registry data into local cache (network)")
    p_refresh.set_defaults(func=cmd_refresh)

    p_scan = sub.add_parser("scan", parents=[common], help="Evaluate packages against local cache only (no network)")
    p_scan.add_argument("--json", action="store_true", help="Emit finding-envelope-conformant JSON instead of human output")
    p_scan.set_defaults(func=cmd_scan)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())