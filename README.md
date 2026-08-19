# VSac (Venom-Sac)

Dependency risk scanner for the [Gossamer Suite](https://github.com/TheVoidThatConsumes/gossamer-suite).

> **Status: early / 0.x.** VSac's local-scan tier (CVE scanning + slopsquatting
> detection) and SBOM export are implemented and tested. **The digest tier
> (KEV/OSSF correlation, composite risk scoring) and license-compliance
> checking are not yet implemented.** See [Roadmap](#roadmap) below before
> depending on this for anything beyond CVE/slopsquat scanning and SBOM export.

## What it does today

- `vsac refresh <target>` — fetches OSV vulnerability data and registry
  metadata for your project's dependencies into a local cache. The only
  command that touches the network.
- `vsac scan <target>` — evaluates cached data and reports findings.
  **Never makes a network call**, by design — see
  [Design](#design-network-isolation) below.
- `vsac sbom <target> [--format cyclonedx|spdx]` — emits an SBOM
  (CycloneDX 1.7 or SPDX 2.3, both current official spec versions) from
  the dependency manifest, printed as JSON on stdout. **Never makes a
  network call**: license fields are best-effort enrichment from the
  refresh cache only, so a BOM works even before `refresh` has run.

Findings cover:
- **Known CVEs** (via [OSV](https://osv.dev)), with real CVSS-derived severity
- **Outdated / stale dependencies** (advisory signals, not vulnerabilities)
- **Slopsquatting** — package names matching patterns commonly seen in
  AI-hallucinated dependencies, and newly-registered packages

## Install

```bash
pip install vsac
```

## Usage

```bash
# From a project directory (auto-detects requirements.txt, package.json/
# package-lock.json, or Cargo.toml/Cargo.lock):
vsac refresh .
vsac scan .
vsac sbom .                          # CycloneDX 1.7 JSON on stdout
vsac sbom requirements.txt --format spdx   # or SPDX 2.3

# Or point at a specific file:
vsac refresh requirements.txt
vsac scan requirements.txt --json
```

Exit codes: `0` clean, `1` a `coverage-gap` finding or a CRITICAL/HIGH
severity finding is present, `2` usage/parse error (`sbom` is `0` on
success / `2` on manifest error — its stdout is the BOM, not a finding
envelope). See `DECISIONS.md`
in the [gossamer-suite](https://github.com/TheVoidThatConsumes/gossamer-suite)
repo for the full rationale.

## Design: network isolation

`vsac scan` never makes a live network call, full stop — not even to
OSV. All vulnerability/registry data comes from a local cache, written
only by the separate `vsac refresh` command. This is deliberate and
tested: plain `import vsac` does not load `requests` at all; it's only
pulled in when `refresh` is explicitly invoked.

## Roadmap

Per the Gossamer Suite's design ledger, in order:
1. ~~Local CVE scanning (OSV-derived local cache)~~ done
2. ~~Slopsquatting detection~~ done
3. ~~SBOM generation (CycloneDX 1.7 / SPDX 2.3)~~ done
4. Digest tier: CISA KEV + OSSF Malicious Packages correlation,
   composite risk scoring, `--explain-score`
5. License compliance (advisory-only)

## Credit

VSac's dependency-file parsers and slopsquatting heuristics are ported
from [XBOM](https://github.com/TheVoidThatConsumes/XBOM) (CC0 1.0 —
no attribution required, credited here as a courtesy).

## License

Apache License, Version 2.0. See [LICENSE](LICENSE).
