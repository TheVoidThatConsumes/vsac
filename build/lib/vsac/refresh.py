"""
vsac/refresh.py — network-only cache writer.

This is one of exactly two places in VSac allowed to touch the network
(the other is the digest tier). Per DECISIONS.md, `vsac scan` must never
make a live call, full stop — so every fetch function that xbom's
scan_one_package called inline now lives here instead, and writes its
result into the cache via vsac.cache rather than returning it for
immediate use in a finding.

Ported near-verbatim from xbom's fetch_pypi / fetch_osv /
fetch_npm_registry / fetch_crates_registry (retry/backoff behavior on
429/5xx is unchanged — that logic isn't about the network-isolation
rule, it's about being a polite API client, and doesn't need rework).

`requests` is the accepted stdlib-first exception, scoped to exactly
this module per DECISIONS.md.
"""

from __future__ import annotations

import time
from typing import Optional

import requests

from . import cache

OSV_API = "https://api.osv.dev/v1/query"
PYPI_API = "https://pypi.org/pypi/{name}/json"
PYPI_VER_API = "https://pypi.org/pypi/{name}/{version}/json"
NPM_API = "https://registry.npmjs.org/{name}"
CRATES_API = "https://crates.io/api/v1/crates/{name}"

TOOL_NAME = "vsac"
TOOL_VERSION = "0.1.0"


def _fetch_pypi(name: str, version: Optional[str] = None):
    url = PYPI_VER_API.format(name=name, version=version) if version else PYPI_API.format(name=name)
    for attempt in range(3):
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                return r.json(), "ok"
            if r.status_code == 404:
                return None, "not_found"
            if r.status_code == 429 or r.status_code >= 500:
                time.sleep(0.5 * (attempt + 1))
                continue
            return None, "error"
        except requests.RequestException:
            time.sleep(0.5 * (attempt + 1))
    return None, "error"


def _fetch_npm(name: str):
    for attempt in range(3):
        try:
            r = requests.get(NPM_API.format(name=name), timeout=10)
            if r.status_code == 200:
                return r.json(), "ok"
            if r.status_code == 404:
                return None, "not_found"
            if r.status_code == 429 or r.status_code >= 500:
                time.sleep(0.5 * (attempt + 1))
                continue
            return None, "error"
        except requests.RequestException:
            time.sleep(0.5 * (attempt + 1))
    return None, "error"


def _fetch_crates(name: str):
    headers = {"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION} (github.com/TheVoidThatConsumes/XBOM)"}
    for attempt in range(3):
        try:
            r = requests.get(CRATES_API.format(name=name), headers=headers, timeout=10)
            if r.status_code == 200:
                return r.json(), "ok"
            if r.status_code == 404:
                return None, "not_found"
            if r.status_code == 429 or r.status_code >= 500:
                time.sleep(0.5 * (attempt + 1))
                continue
            return None, "error"
        except requests.RequestException:
            time.sleep(0.5 * (attempt + 1))
    return None, "error"


def _fetch_osv(name: str, version: Optional[str], ecosystem: str = "PyPI"):
    if not version:
        return [], "ok"
    try:
        r = requests.post(
            OSV_API,
            json={"package": {"name": name, "ecosystem": ecosystem}, "version": version},
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("vulns", []), "ok"
        return [], "error"
    except requests.RequestException:
        return [], "error"


def _fetch_registry(name: str, ecosystem: str):
    if ecosystem == "npm":
        return _fetch_npm(name)
    if ecosystem == "rust":
        return _fetch_crates(name)
    return _fetch_pypi(name)


def refresh_packages(packages: list[tuple[str, Optional[str]]], ecosystem: str = "PyPI",
                      cache_dir=cache.DEFAULT_CACHE_DIR) -> dict:
    """
    Fetch OSV + registry metadata for each (name, version) and write the
    results into the local cache. This is the only function in VSac that
    is allowed to originate from `vsac refresh` on the CLI.

    Returns a summary dict: {"refreshed": int, "osv_errors": int, "registry_errors": int}.
    """
    entries = []
    osv_errors = 0
    registry_errors = 0

    for name, version in packages:
        vulns, osv_status = _fetch_osv(name, version, ecosystem=ecosystem)
        meta, registry_status = _fetch_registry(name, ecosystem)

        if osv_status == "error":
            osv_errors += 1
        if registry_status == "error":
            registry_errors += 1

        entries.append((name, version, {
            "osv_vulns": vulns,
            "osv_status": osv_status,
            "registry_meta": meta,
            "registry_status": registry_status,
        }))

    cache.put_entries(entries, ecosystem=ecosystem, cache_dir=cache_dir)

    return {
        "refreshed": len(entries),
        "osv_errors": osv_errors,
        "registry_errors": registry_errors,
    }