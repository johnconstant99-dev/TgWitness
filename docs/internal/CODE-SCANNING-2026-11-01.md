# Code scanning remediation — 1 November 2026

This follow-up reviews the authenticated GitHub Code scanning results after
`973fefcb11c015f467af07a50f5563fd922d6bf9`. It supplements the earlier
[dated security audit](SECURITY-AUDIT-2026-11-01.md); that document remains a
record of the code and scans at the time. English is the canonical language.

## Starting inventory

All pages of the open-alert API were collected, not just the first page.
The initial inventory contained **180 open alerts**:

| Tool | Open alerts | Interpretation |
| --- | ---: | --- |
| Trivy | 73 | Package/CVE records across three images; 30 distinct CVEs |
| zizmor | 58 | Workflow references, permissions, definitions and runner policy |
| CodeQL | 18 | Python boundaries, fixtures and legacy-format cryptography |
| OpenSSF Scorecard | 31 | 26 dependency-pinning records and five process assessments |

Counts are scanner records, not a count of demonstrated remote exploits.
No blanket suppression, severity reduction or `ignore-unfixed` exemption was
introduced. One existing alert, #95, was individually dismissed as a confirmed
false positive after the source and protocol review below. Only a subsequent
default-branch scan can establish which other GitHub alerts close.

## Source boundaries and compatibility

| Alerts | Change and evidence |
| --- | --- |
| #81–84, media paths | Express the existing 64-character lowercase hexadecimal contract with `re.fullmatch`. Scope membership checks, symlink rejection and inline-media fallback remain. Regression probes cover authentication, scoped access, encoded traversal, Unicode, newline and length boundaries. No bypass of the earlier HTTP guard was demonstrated. |
| #85–86, locale paths | Load only files from fixed supported-language path catalogs. This enforces the contract inside the loader as well as at HTTP callers. Unsupported direct calls perform no file read. |
| #96, report control characters | Replace an ambiguous regex with an explicit set of the same 76 control/bidirectional code points. Exhaustive Unicode comparison established equivalence. The policy applies to report metadata, not authoritative message text. |
| #79 and follow-up #208, fixture script filter | Parse the repository-owned fixture with the browser's inert DOM parser and remove script elements before loading it. This handles browser tag syntax without a regex filter. It is not a general-purpose HTML sanitizer. |
| #80, diagram parser | The expression recognizes Mermaid arrows; rendered labels pass through HTML escaping. A markup probe verifies the boundary. No production sanitizer is replaced with a regex. |
| #87, publication scanner | A synthetic secret canary confirms output contains only the location, pattern and `value withheld`, not the matched bytes. |
| #88, #90, synthetic fixtures | Fixed test values and generated TData are synthetic. Tests do not load an operator's credentials. |
| #89, #91–95, TData primitives | Preserve Telegram Desktop compatibility: the AES single-block operation participates in IGE chaining; SHA-1 derives the legacy key/IV; the SHA-512 prehash feeds PBKDF2-SHA-512 with the format's passcode-dependent iteration count. Empty, nonempty, wrong and corrupt passcode cases are checked. These are legacy import requirements, not recommendations for new encryption formats. |

The new [boundary check](../../tools/check_codeql_boundaries.py) runs in PR CI.
The original format can be compared with Telegram Desktop's
[passcode derivation](https://github.com/telegramdesktop/tdesktop/blob/5ff615713d2178b8458e201778d23d7abe78db9b/Telegram/SourceFiles/storage/details/storage_file_utilities.cpp#L372)
and [key/IV derivation](https://github.com/telegramdesktop/tdesktop/blob/5ff615713d2178b8458e201778d23d7abe78db9b/Telegram/SourceFiles/mtproto/mtproto_auth_key.cpp#L43).
Scanner warnings about those required primitives can remain after analysis.
Alert #95 specifically treats the intermediate SHA-512 digest as a standalone
password hash. The next statement passes it to PBKDF2-HMAC-SHA-512, exactly as
the referenced Desktop format specifies. Its dismissal records that reasoning
and the passcode regressions; it does not dismiss the other legacy crypto alerts.

## Workflow and dependency controls

Twelve mutable action references are replaced with full upstream commit SHAs,
with annotated tags resolved to their commits. Jobs have explicit names;
write permissions are explained and restricted to the jobs that need them.
Shell commands read runtime environment variables instead of interpolating
workflow expressions into shell source. Dependabot has a seven-day cooldown.
CodeQL now analyzes main pushes, pull requests and merge queues with the same
language categories and extended queries. Scheduled/manual runs retain the
dependency and actual-image audits.

CI installs separately scoped, hash-locked audit, site, browser and MCP
dependencies. A pre-install check rejects changed lock inputs. The media
worker also uses an exact transitive lock and only verified wheel artifacts;
the runtime and media Docker bases use the existing reviewed sealed-image
digest. The six new lock/input files are explicitly included in public source
archives. Local reviewed project code is installed separately with
`--no-deps --no-build-isolation`.

All four CI dependency scopes passed clean Windows installations and `pip check`,
and Linux Python 3.12 resolution. Media artifacts were checked against PyPI
hashes, downloaded for Linux, and tested with a deliberately wrong hash.
Fresh-cache advisory queries found no known vulnerabilities in the five new
lock scopes for the local platform's selected markers; scheduled CI audits
the Linux selection too. The actual restricted Linux container check now
imports transcription dependencies offline in addition to exercising OCR.
An import check does not substitute for a model-backed transcription test.

The repository SBOM continues to declare its explicit runtime/build/optional-MCP
scope. A real Syft 1.55 scan of this tree matched all 54 distinct frozen Python
pins. Its scope is not a complete inventory of CI tooling or Debian packages.

Offline zizmor no longer reports the addressed action-reference, definition,
permission, template-injection or cooldown groups. Its eleven self-hosted
runner warnings remain: these runners execute reviewed repository code;
untrusted PR checks use GitHub-hosted runners. The same-commit reusable
workflow uses `./.github/workflows/checks.yml`; the suggested `$/` spelling
is not accepted by the currently validated actionlint version.

The pinned sealed signer `eab5169e400ff3010d8853f42c8e430fe23ffe6b`
had no reference in the current public history, causing the impostor/stale-ref
warnings. The annotated archival tag
[`archive/sealed-signer-eab5169e400f`](https://github.com/phishdestroy/TgWitness/tree/archive/sealed-signer-eab5169e400f)
retains that exact reviewed commit, its collector parent and the older approved
pair in their ancestry. It is not a release or a cryptographic signing claim.
The verifier's exact accepted SHA pairs remain authoritative and unchanged.
The historical tag triggers only hosted synthetic sealed validation; it does
not launch a production capture or publish release assets.
That historical run passed the real synthetic attestation check; its old test
suite reported one policy/workflow pin mismatch because the archived workflow
commit predates the subsequent policy promotion. The archival reference preserves
those historical bytes and is not presented as a newly validated release.

Scorecard process findings require actual review history, repository age,
fuzzing or a best-practices assessment. The OSSF wrapper's action commit is
pinned, but its internal version-tagged container is an upstream limitation.
No fabricated approvals, badge claims or historical scan coverage were added.

## Remaining container findings

The baseline image reports contain runtime/sealed **46 records and 10 distinct
CVEs each**, and media **73 records and 30 distinct CVEs**. All 30 were still
listed as vulnerable for stable Debian 13 during this review; no compatible
stable fixed package version was found. Pinning the base makes the selected
image reproducible; it does not remove these findings.

The [libxml2 issue](https://security-tracker.debian.org/tracker/CVE-2026-6653)
is critical in Trivy and minor/no-dsa in Debian; both assessments are retained.
The [SQLite FTS5 issue](https://security-tracker.debian.org/tracker/CVE-2026-119373)
requires `detail=none` and negative row IDs, unlike the journal's ordinary
index configuration. The [SQLite recovery issue](https://security-tracker.debian.org/tracker/CVE-2026-119586)
targets the CLI recovery pipeline. Reviewed Tesseract findings require crafted
model data; the worker selects installed models and does not accept an uploaded
model file. These observations narrow documented paths without claiming every
untrusted-media decoder path is safe.

Read-only filesystems, a dropped capability set, no new privileges, network
isolation and resource limits remain part of the media worker boundary.
Custom privileged deployments are outside those assumptions. The high/critical
image gate remains enabled and is expected to fail while these packages remain
affected. Rebuild and rescan after stable security updates become available.
