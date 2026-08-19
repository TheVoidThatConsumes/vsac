"""
vsac/sbom.py — SBOM generation (CycloneDX 1.7 / SPDX 2.3).

Pure transformation of a parsed dependency list into a standards-
conformant BOM document. No network calls, ever: unlike xbom's
build_sbom (which enriched components with live per-package registry
lookups), the only I/O here is reading the local cache that
`vsac refresh` populated — a cached entry's license is best-effort
enrichment; an absent or failed entry simply yields a component
without license fields. It never fetches, and it never fails a BOM
because refresh hasn't run yet.

Two formats, both widely consumed and both named in EU CRA (Regulation
(EU) 2024/2847, Article 13 / Annex I) guidance for machine-readable
SBOMs:
  - CycloneDX 1.7 JSON — https://cyclonedx.org/ (current spec version;
    tools emitted in the modern `tools.components` form, the legacy
    flat-array form being deprecated)
  - SPDX 2.3 JSON — https://spdx.github.io/spdx-spec/v2.3/

Per DECISIONS.md, `vsac sbom` is a data-export command: its stdout IS
the BOM document, so the "--json always emits a finding envelope" rule
(which governs scan's report output) does not apply here. Exit codes:
0 on success, 2 on manifest/usage errors (message on stderr, no
partial BOM ever printed).

CRA minimum coverage is top-level dependencies — exactly what the
manifest parsers produce, so every component carries scope "required"
(CycloneDX) / a DEPENDS_ON relationship from the root (SPDX).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from importlib.metadata import PackageNotFoundError, version as _dist_version

from . import cache

try:
    _VERSION = _dist_version("vsac")
except PackageNotFoundError:
    _VERSION = "unknown"

_PURL_SCHEME = {"PyPI": "pypi", "npm": "npm", "rust": "cargo"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _purl(name: str, version: Optional[str], ecosystem: str) -> str:
    """Package-URL per the purl spec (https://github.com/package-url/purl-spec).

    PyPI names are lowercased: the ecosystem is case-insensitive and
    the canonical purl form is lowercase. npm/cargo names are already
    lowercase by registry rule and are kept as declared.
    """
    scheme = _PURL_SCHEME.get(ecosystem, "pypi")
    n = name.lower() if scheme == "pypi" else name
    return f"pkg:{scheme}/{n}@{version}" if version else f"pkg:{scheme}/{n}"


def _license_from_registry(meta, ecosystem: str, version: Optional[str]) -> Optional[str]:
    """Best-effort license extraction from cached registry_meta.

    Same extraction xbom performed against live registry responses,
    now sourced exclusively from the local cache. Returns None when
    the entry is absent, failed, or carries no license — never a
    synthetic "unknown" string.
    """
    if not isinstance(meta, dict):
        return None

    if ecosystem == "PyPI":
        info = meta.get("info") or {}
        lic = info.get("license") or ""
        if not lic:
            # PyPI often leaves the `license` field blank even when the
            # license is declared via trove classifiers — fall back to
            # them before giving up.
            classifiers = info.get("classifiers") or []
            license_classifiers = [c for c in classifiers if c.startswith("License ::")]
            if license_classifiers:
                lic = license_classifiers[0].split(" :: ")[-1]
        return lic or None

    if ecosystem == "npm":
        versions = meta.get("versions") or {}
        vmeta = versions.get(version) if version else None
        return (vmeta or {}).get("license") or meta.get("license") or None

    if ecosystem == "rust":
        versions = meta.get("versions") or []
        if version:
            vmeta = next((v for v in versions if v.get("num") == version), None)
        else:
            vmeta = versions[0] if versions else None
        return (vmeta or {}).get("license") or None

    return None


def _cached_license(name: str, version: Optional[str], ecosystem: str, cache_dir: Path) -> Optional[str]:
    """License for (name, version) if the refresh cache has registry metadata for it."""
    entry = cache.get_entry(name, version, ecosystem=ecosystem, cache_dir=cache_dir)
    if not entry:
        return None
    return _license_from_registry(entry.get("registry_meta"), ecosystem, version)


def _cyclonedx(packages: list, ecosystem: str, product_name: str, cache_dir: Path) -> dict:
    components = []
    for name, version in packages:
        comp: dict = {
            "type": "library",
            "name": name,
            "scope": "required",  # top-level dependency, per CRA's minimum coverage
            "purl": _purl(name, version, ecosystem),
        }
        if version:
            comp["version"] = version
        lic = _cached_license(name, version, ecosystem, cache_dir)
        if lic:
            comp["licenses"] = [{"license": {"name": lic}}]
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            # 1.7-canonical tools shape: the generator as a component.
            # The legacy flat tool-array form is deprecated in the schema.
            "tools": {"components": [{"type": "application", "name": "vsac", "version": _VERSION}]},
            "component": {"type": "application", "name": product_name},
        },
        "components": components,
    }


def _spdx(packages: list, ecosystem: str, product_name: str, cache_dir: Path) -> dict:
    doc_namespace = f"https://spdx.org/spdxdocs/{product_name}-{uuid.uuid4()}"

    spdx_packages: list[dict] = [
        {
            "SPDXID": "SPDXRef-Package-root",
            "name": product_name,
            "versionInfo": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "filesAnalyzed": False,
            "primaryPackagePurpose": "APPLICATION",
        }
    ]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-root",
        }
    ]

    for i, (name, version) in enumerate(packages):
        spdx_id = f"SPDXRef-Package-{i}-{re.sub(r'[^A-Za-z0-9.]', '-', name)}"
        lic = _cached_license(name, version, ecosystem, cache_dir)
        spdx_packages.append({
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": version or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": lic or "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": _purl(name, version, ecosystem),
                }
            ],
        })
        relationships.append({
            "spdxElementId": "SPDXRef-Package-root",
            "relationshipType": "DEPENDS_ON",  # top-level dependency, per CRA's minimum coverage
            "relatedSpdxElement": spdx_id,
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{product_name}-sbom",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": _now(),
            "creators": [f"Tool: vsac-{_VERSION}"],
        },
        "packages": spdx_packages,
        "relationships": relationships,
    }


def build_sbom(packages: list[tuple[str, Optional[str]]], ecosystem: str,
               product_name: str, fmt: str = "cyclonedx",
               cache_dir: Optional[Path] = None) -> dict:
    """
    Build a BOM document from a parsed dependency list.

    packages: [(name, version-or-None), ...] exactly as the manifest
        parsers return them.
    fmt: "cyclonedx" (default) or "spdx".
    cache_dir: override for the refresh cache root; defaults to
        cache.DEFAULT_CACHE_DIR. Only ever read, never written.
    """
    if fmt not in ("cyclonedx", "spdx"):
        raise ValueError(f"unknown SBOM format: {fmt!r} (expected 'cyclonedx' or 'spdx')")
    cache_root = Path(cache_dir) if cache_dir else cache.DEFAULT_CACHE_DIR
    if fmt == "cyclonedx":
        return _cyclonedx(packages, ecosystem, product_name, cache_root)
    return _spdx(packages, ecosystem, product_name, cache_root)
