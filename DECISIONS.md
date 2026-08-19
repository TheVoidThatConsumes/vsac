# VSac — Decisions

> Provenance note: this file was reconstructed from the decision records
> embedded in the module docstrings (scan.py, refresh.py, cache.py,
> parsers.py, schema.py, cli.py, slopsquat.py) and the README's exit-code
> contract, because the original DECISIONS.md did not exist in the repo
> while ~20 code sites referenced it. Nothing here is new policy — each
> entry states the locked behavior the code already enforces, and names
> the enforcing site. If a future change updates one of these decisions,
> update BOTH this file and the corresponding docstring.

## 1. Offline-first: `vsac scan` must never touch the network

Not even indirectly. Every fetch function that xbom's `scan_one_package`
called inline now lives in `vsac/refresh.py`, the network-only cache
writer. `vsac scan` is a pure reader of what `refresh` already wrote via
`vsac.cache`. `requests` is the accepted stdlib-first exception, scoped
to exactly `refresh.py`.

- Enforcing sites: `refresh.py` (module docstring), `cache.py` (module
  docstring: "sole boundary between `vsac refresh` (the only writer) and
  `vsac scan` (a reader only)"), `scan.py` (module docstring: "no
  network calls, ever").

## 2. Refresh/scan separation was the fix, not a conditional skip

xbom's violation was *interleaving* fetch + finding logic in one
function. The fix is a full separation of modules, not a runtime check.
Consequence: the per-package ThreadPoolExecutor is gone — it existed
only to parallelize network round-trips.

- Enforcing sites: `scan.py` module docstring.

## 3. coverage-gap: cache incompleteness is a build-breaking condition

Locked, not up for re-litigation as "just treat it like an error":

- `coverage-gap` is **not a severity-scale finding**. It is excluded
  from any aggregate/rollup score and forces a non-zero exit independent
  of every other finding in the scan.
- Its definition is narrow: **"package not in cache"** — a
  cache-completeness concept. It must not be reused for other
  "could not run" conditions (see §5).
- On the envelope: the finding carries `severity: INFO` only to satisfy
  the schema's required field, and is marked `non_scored: true` so the
  controller's fail-closed gate treats it correctly. Consumers key off
  `non_scored`, never off the INFO value.

- Enforcing sites: `scan.py` (module docstring, `exit_code_for`),
  `schema.py` (`_is_non_scored`, `_severity_for`), `cli.py` (exit 1 on
  any coverage-gap regardless of `--gate`).

## 4. lookup-error: two distinct conditions, two different treatments

- **Refresh failure** (the cache records that an OSV/registry fetch WAS
  attempted and failed): a real severity — MEDIUM, not INFO — because
  it blocks a real assessment and shouldn't be ignorable as pure noise.
  Scored; participates in the gate normally.
- **Declined manifest** (the manifest was recognized but refused by
  policy; no packages were ever extracted): the synthetic finding is a
  `lookup_error` whose `declined_manifest` marker makes it
  `non_scored: true`. The manifest was refused, so no real assessment
  happened — fail closed, like coverage-gap, even though the category is
  different.

- Enforcing sites: `schema.py` (`_is_non_scored`), `cli.py`
  (`_emit_unsupported_manifest`).

## 5. Manifest-format coverage addendum

Locked scope for `parse_pyproject` (`parsers.py`):

- **PEP 621 `[project.dependencies]`**: parsed. A fixed, bounded spec
  (an array of PEP 508 strings), not an open-ended format.
- **Poetry `[tool.poetry.dependencies]`**: recognized but NOT parsed.
  Its version-constraint syntax (`^1.2.3`, `~1.2`) is not PEP
  508-compatible; parsing it correctly is separate scope. Raises
  `UnsupportedManifestError` — a *stated decline*, not silence. The
  CLI path for this is a synthetic `lookup_error` finding with a
  non-zero exit (see §4), not a bare usage error.
- **Anything else**: raises `ParseError` — nothing VSac recognizes at
  all, same category as a missing/unreadable `requirements.txt`.
- **`[project.optional-dependencies]`**: deliberately NOT parsed in this
  pass; flagged as a separate follow-up rather than folded in
  opportunistically (same anti-scope-creep caution as Poetry).

## 6. Severity defaults for advisory categories (no CVE data)

Known-vulnerability derives severity straight from cached OSV data.
The other categories have no CVE data, so severity is locked per
category (`schema.py` `_ADVISORY_SEVERITY`):

| category          | severity | rationale                                                        |
|-------------------|----------|------------------------------------------------------------------|
| slopsquatting     | HIGH     | active-attack pattern, not hygiene                                |
| dependency-outdated | LOW    | fixed version exists, no active exploit                          |
| dependency-stale  | INFO     | hygiene signal, not security                                      |
| lookup-error      | MEDIUM   | blocks real assessment, shouldn't be noise                        |
| coverage-gap      | INFO     | explicitly excluded from the severity scale (see §3)              |

## 7. Exit-code contract

- `0` — clean scan.
- `1` — any severity finding present **or** any coverage-gap **or** a
  declined manifest. Coverage-gap forces 1 even if the severity scan is
  clean: cache incompleteness must surface as build-breaking on its own.
- `2` — usage/parse error (there is nothing to scan here).

- Enforcing sites: `cli.py` (`cmd_scan` return paths), `scan.py`
  (`exit_code_for`), README.

## 8. Fail-closed principle

Where a deviation from a "ported with zero drift" baseline is needed to
keep a security signal actually firing, the flagged deviation wins. The
concrete case: xbom's `days_since()` read PyPI's `upload_time` (naive,
no timezone suffix), `fromisoformat()` produced a naive datetime,
subtraction against `datetime.now(timezone.utc)` raised `TypeError`,
and xbom's bare `except Exception` silently swallowed it — the STALE
check never fired, for every PyPI package, always. VSac assumes UTC
for PyPI's naive timestamps instead of leaving the comparison broken.

- Enforcing site: `slopsquat.py` (`days_since`).

## 9. Documented deviations from the xbom port

1. `parse_requirements` no longer calls `sys.exit()` on a bad path —
   parse errors raise `ParseError` and the caller decides (print +
   exit, or orchestrate). Control-flow change only, no change to
   parsing logic. (`parsers.py` module docstring.)
2. The UTC fix in §8. (`slopsquat.py` `days_since`.)

## 10. Not implemented (future scope)

The digest tier is not implemented. When it ships, it is the second
place allowed to touch the network (`refresh.py` module docstring names
it as such).

## 11. SBOM generation (`vsac sbom`)

Shipped as a data-export command in the same offline-first posture as
`scan` — a port of xbom's `build_sbom` that fixes its one structural
violation (live per-package registry enrichment) and modernizes its
formats:

- **Offline-only, cache-backed license enrichment.** xbom's builder
  called `fetch_npm_registry` / `fetch_crates_registry` /
  `resolve_package` live while assembling the BOM. VSac's builder reads
  only the refresh cache: `cache.get_entry(...).registry_meta` is the
  sole license source. A missing or failed entry yields a component
  with no license fields — never a synthetic "unknown", and never a
  failed BOM because refresh hasn't run yet. `sbom.py` imports nothing
  that touches the network.
- **Formats: CycloneDX 1.7 + SPDX 2.3**, both validated against the
  official schemas. CycloneDX 1.7 is the current spec version (the
  legacy flat `tools` array form is deprecated; the modern
  `tools.components` form is emitted, `serialNumber` in the required
  `urn:uuid:` form). SPDX 2.3 is the widely-consumed JSON SPDX format
  (`filesAnalyzed: false`, purl `externalRefs` with
  `referenceCategory: PACKAGE-MANAGER`). SPDX 3.x JSON is noted but not
  emitted: 2.3 remains the format the tooling/consumer ecosystem
  accepts. Both formats are named in EU CRA (Regulation (EU) 2024/2847,
  Article 13 / Annex I) guidance for machine-readable SBOMs.
- **CRA minimum coverage = top-level dependencies.** The manifest
  parsers produce exactly that, so every component is `scope:
  "required"` (CycloneDX) / `DEPENDS_ON` from the root package (SPDX).
  No transitive-resolution attempt — same scope line as the parsers.
- **stdout IS the BOM; no envelope contract.** Unlike `scan --json`,
  which emits a finding envelope, `sbom`'s stdout is the document
  itself, so the "--json emits a finding envelope" rule does not apply
  (cli.py module docstring). No SBOMs/ directory, no history file —
  xbom's file-writing side effects were dropped; piping stdout is the
  contract.
- **Exit codes: 0 success, 2 manifest/usage error** (message on stderr,
  no partial BOM ever printed — same shape as `refresh`'s parse-error
  path, including a declined Poetry manifest).

- Enforcing sites: `sbom.py` (module docstring, `_purl`, `_cached_license`),
  `cli.py` (`cmd_sbom`), `__init__.py` (sbom imported eagerly — it is
  offline-safe, unlike `refresh`).
