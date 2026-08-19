"""
vsac/cache.py — local, on-disk dependency-metadata cache.

This module makes NO network calls, ever. It is the sole boundary between
`vsac refresh` (the only writer) and `vsac scan` (a reader only). Per
DECISIONS.md, `vsac scan` must never touch the network, not even
indirectly — so this module's job is to make "is this package cached"
and "what does the cache say about it" answerable with zero I/O beyond
the local filesystem.

Cache layout: one JSON file per ecosystem under the cache root, keyed by
"name@version" (version "None" is a valid, explicit key for unpinned
deps — never coerced to "latest").

    <cache_root>/PyPI.json
    <cache_root>/npm.json
    <cache_root>/rust.json

Each entry:
    {
      "name": str,
      "version": str | null,
      "fetched_at": ISO8601 str,
      "osv_vulns": [ ... raw OSV vuln dicts ... ],
      "osv_status": "ok" | "error",
      "registry_meta": { ... raw registry response, or null ... },
      "registry_status": "ok" | "not_found" | "error",
    }

A missing entry is NOT the same as an entry with empty/failed status —
absence means "never refreshed," which is the trigger for a
coverage-gap finding in scan.py. An entry that IS present but whose
registry_status/osv_status is "error" reflects a refresh-time failure;
scan.py treats that as data (a lookup_error finding), not as absence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_CACHE_DIR = Path.home() / ".vsac" / "cache"

_ECOSYSTEM_FILENAMES = {
    "PyPI": "PyPI.json",
    "npm": "npm.json",
    "rust": "rust.json",
}


def _cache_file(ecosystem: str, cache_dir: Path = DEFAULT_CACHE_DIR) -> Path:
    filename = _ECOSYSTEM_FILENAMES.get(ecosystem, f"{ecosystem}.json")
    return Path(cache_dir) / filename


def _cache_key(name: str, version: Optional[str]) -> str:
    return f"{name.lower()}@{version if version else 'None'}"


def load_ecosystem_cache(ecosystem: str, cache_dir: Path = DEFAULT_CACHE_DIR) -> dict:
    """Return the full on-disk cache dict for one ecosystem. {} if absent/corrupt."""
    path = _cache_file(ecosystem, cache_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # A corrupt cache file is treated identically to a missing one:
        # every lookup against it becomes a coverage-gap, fail-closed,
        # never a crash and never a silent "assume empty is fine."
        return {}


def save_ecosystem_cache(ecosystem: str, data: dict, cache_dir: Path = DEFAULT_CACHE_DIR) -> None:
    path = _cache_file(ecosystem, cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def get_entry(name: str, version: Optional[str], ecosystem: str = "PyPI",
              cache_dir: Path = DEFAULT_CACHE_DIR) -> Optional[dict]:
    """
    Return the cache entry for (name, version) in this ecosystem, or None
    if it has never been refreshed. This None is the sole signal scan.py
    uses to emit a coverage-gap finding — no other code path should
    invent a substitute for "not cached."
    """
    data = load_ecosystem_cache(ecosystem, cache_dir)
    return data.get(_cache_key(name, version))


def put_entry(name: str, version: Optional[str], entry: dict, ecosystem: str = "PyPI",
              cache_dir: Path = DEFAULT_CACHE_DIR) -> None:
    """Write/overwrite one entry. Called only from refresh.py."""
    data = load_ecosystem_cache(ecosystem, cache_dir)
    entry = dict(entry)
    entry.setdefault("name", name)
    entry.setdefault("version", version)
    entry["fetched_at"] = datetime.now(timezone.utc).isoformat()
    data[_cache_key(name, version)] = entry
    save_ecosystem_cache(ecosystem, data, cache_dir)


def put_entries(entries: list[tuple[str, Optional[str], dict]], ecosystem: str = "PyPI",
                 cache_dir: Path = DEFAULT_CACHE_DIR) -> None:
    """Batch write — one file read/write instead of N, for a full refresh run."""
    data = load_ecosystem_cache(ecosystem, cache_dir)
    now = datetime.now(timezone.utc).isoformat()
    for name, version, entry in entries:
        entry = dict(entry)
        entry.setdefault("name", name)
        entry.setdefault("version", version)
        entry["fetched_at"] = now
        data[_cache_key(name, version)] = entry
    save_ecosystem_cache(ecosystem, data, cache_dir)