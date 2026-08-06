# VSac

Dependency vulnerability scanning, SBOM generation, and threat correlation for the [Gossamer Suite](https://github.com/TheVoidThatConsumes/gossamer-suite) with a hard line between "fetch data" and "evaluate data" so scans stay offline and deterministic by default.

| | |
|---|---|
| **Status** | Planned — local scan tier in active design |
| **License** | Apache 2.0 (code) · CC BY 4.0 (documentation) |
| **Language** | Python 3.12+ |
| **Suite** | Part of [Gossamer Suite](https://github.com/TheVoidThatConsumes/gossamer-suite) — independently installable, independently versioned |
| **Maintainer** | David Obi ([@TheVoidThatConsumes](https://github.com/TheVoidThatConsumes)) |

---

## Overview

VSac scans a project's dependencies for known vulnerabilities, generates a software bill of materials, and (optionally) correlates findings against a signed threat intelligence feed. It is the only Gossamer suite member that legitimately needs the network. CVE and registry data goes stale, but it never makes that tradeoff silently or mid-scan.

VSac is split into three commands, each with a single responsibility:

```
vsac refresh    fetches CVE and registry data, writes it to a local cache — the only network I/O in VSac
vsac scan       evaluates dependencies against the local cache — zero network calls, ever
vsac digest     correlates cached findings against KEV / OSSF signals via a signed snapshot — opt-in
```

This split exists because `scan` is a pure, offline, deterministic function of what's on disk. It cannot make a live API call per package, interleaved with the rest of the scan logic, which means that CI runs are only as reliable as an upstream registry's uptime, and two runs against the same commit could produce different findings depending on when they happened to run. `refresh` is the only place staleness enters the picture explicitly, on request.

---

## Usage

```bash
vsac refresh                  # populate/update the local CVE + registry cache (network)
vsac scan                     # evaluate current dependencies against the cache (offline)
vsac scan --json              # emit a Gossamer finding-envelope report
vsac digest                   # correlate cached findings against the signed threat feed (network, opt-in)
vsac audit                    # generate SBOM → refresh → scan → digest, end to end
```

`vsac scan` never fails open on missing data. A dependency with no matching cache entry (never refreshed, or newly added since the last `refresh`) produces an explicit `inconclusive` finding rather than being silently treated as clean. The scan's exit code reflects this: any inconclusive findings are a soft-fail, distinct from a clean pass, so CI surfaces "you need to run `refresh`" instead of quietly passing on incomplete data.

```bash
vsac refresh && vsac scan --gate HIGH --json | jq -e '.summary.CRITICAL == 0'
```

---

## Cache and staleness

`vsac refresh` is the only command that writes to the local cache, and the only command in VSac that touches the network for CVE/registry lookups. There is no per-scan fallback to a live API call by design.

This means:

- **Outdated-version detection** compares a dependency against "latest as of the last `refresh`," not real-time registry state. An `OUTDATED` finding can itself be stale if the cache hasn't been refreshed recently. Check `vsac refresh`'s last-run timestamp, surfaced in every scan report, before treating an `OUTDATED` flag as current.
- **CVE coverage** reflects OSV (and ecosystem registries) as of the last `refresh`, not the moment `scan` ran.
- A CI pipeline that runs `vsac scan` without ever running `vsac refresh` will get `inconclusive` findings for everything and a non-zero exit. This is intentional, not a bug to route around.

---

## Digest mode

`vsac digest` is VSac's second and final network touchpoint. It pulls a signed, offline-verifiable snapshot from [gossamer-threat-feed](https://github.com/TheVoidThatConsumes/gossamer-threat-feed) (Ed25519-signed, fail-closed, verified on every read) and correlates it against cached CVE data, surfacing which known vulnerabilities are under active exploitation (CISA KEV) or otherwise elevated, and computing a `risk_score` per finding.

`digest` is a generic client of gossamer-threat-feed's signed-snapshot protocol. gossamer-threat-feed itself has no dependency on VSac and can be consumed standalone.

---

## Finding schema

VSac findings conform to Gossamer's shared [finding-envelope schema](https://github.com/TheVoidThatConsumes/gossamer-suite/blob/main/schema/finding-envelope.schema.json), `id`-prefixed `VS-`. Category slugs are drawn from the shared taxonomy:

| Category | Description |
|---|---|
| `known-vulnerability` | Dependency has a published CVE |
| `actively-exploited` | Vulnerability confirmed under active exploitation (e.g. CISA KEV) [digest mode only] |
| `malicious-package` | Package confirmed malicious or part of a known campaign |
| `slopsquatting` | Package name matches a common AI-hallucinated dependency pattern |
| `license-conflict` | Dependency license conflicts with declared project license |

`risk_score` and `source` are VSac-specific extension fields permitted by the schema's open `additionalProperties` and must not be relied on by generic suite tooling (`gossamer audit`, Web), only by VSac-aware consumers.

---

## Explicit scope-creep rejections

Documented to avoid re-litigating:

- MITRE ATT&CK-style actor attribution
- Predictive intelligence
- Context-aware per-repo scoring
- Real-time cross-tool propagation graphs
- Live per-scan network calls (the `refresh`/`scan` split exists specifically to prevent this)

See `DECISIONS.md` for full rationale on each.

---

## Architecture

```
vsac refresh  ──────▶  network  ──────▶  local cache
                                              │
vsac scan     ◀───── reads only ─────────────┘   (zero network)
                                              │
vsac digest   ──────▶  network (signed)  ────┘   (opt-in)
```

VSac is the one Gossamer suite member that straddles the suite's core invariant — most of it runs fully offline like every other tool, but it carries the suite's authorized threads to the outside world, confined to `refresh` and `digest` and nowhere else.

---

## Status and roadmap

| Milestone | Status |
|---|---|
| Local scan tier (`refresh` / `scan`, cache format, xbom port) | In design |
| SBOM generation | Planned, reworked from xbom's live-enrichment version to cache-backed |
| `digest` mode | Planned, blocked on gossamer-threat-feed's signing pipeline |
| Suite registration (`gossamer-suite`'s `registry.py`) | Blocked on first conformant `--json` release |

---

## License

- **Code**: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- **Documentation**: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
