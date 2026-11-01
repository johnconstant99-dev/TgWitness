# Security audit review — 1 November 2026

This records the first [nightly workflow run](https://github.com/phishdestroy/TgWitness/actions/runs/41328030758)
against commit `b71188ebb227b92d25c869b032f1757a416f37f8`, and the follow-up review.
It is a dated result, not a claim that the software has no vulnerabilities.

## Dependency and container results

The runtime, build and optional MCP advisory jobs passed. All three CodeQL
languages completed and uploaded findings. All three container jobs failed their
high/critical vulnerability gate; their SARIF uploads succeeded.

| Built image | Package/CVE findings | Distinct CVEs | Severity |
| --- | ---: | ---: | --- |
| Runtime | 46 | 10 | High |
| Sealed collector | 46 | 10 | High |
| Media worker | 73 | 30 | 72 high, 1 critical |

These are Debian OS packages, with repeated CVEs across binary packages and
images. There are 30 distinct CVEs across the three images. No Python-library
finding appeared in these container reports. Every finding has an empty fixed
version field. The [Debian tracker data](https://security-tracker.debian.org/tracker/data/json)
independently listed all 30 as open for Debian 13 (trixie) during this review.

An ordinary rebuild or package upgrade has not been demonstrated to clear these
findings. The supported Debian 12 (bookworm) alternative is also listed as
vulnerable for the examples below. No base switch, unstable distribution,
blanket ignore, severity reduction or `ignore-unfixed` exemption was applied.
The container gate remains red until its findings are resolved.

| Finding | Exposure review and limit |
| --- | --- |
| [libxml2 CVE-2026-6653](https://security-tracker.debian.org/tracker/CVE-2026-6653) | Trivy rates this **critical**; Debian describes a crafted-XML use-after-free/denial of service and marks stable releases **minor/no-dsa**. Both ratings are preserved. This review does not establish a remotely exploitable critical path in TgWitness. Bookworm and trixie remain vulnerable; a fixed unstable package is not a validated replacement. |
| [SQLite CVE-2026-119373](https://security-tracker.debian.org/tracker/CVE-2026-119373) | The published trigger requires a `detail=none` FTS5 table, negative row IDs and a prefix MATCH query. [Journal indexes](../../tgwitness/journal_index.py) use default full-detail FTS5, and [Store.append](../../tgwitness/store.py) assigns increasing sequences starting at 1 as index row IDs. The normal ingestion/search path does not meet those conditions. The installed SQLite finding remains. |
| [util-linux CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | The issue involves privileged mount-helper post-hooks. Default [Compose deployment](../../compose.yaml) drops all capabilities and sets `no-new-privileges`; the [media worker launcher](../../tgwitness/media_analysis.py) also uses a read-only, networkless container with those restrictions. These controls limit the documented path, but do not remove the vulnerable packages or cover custom privileged deployments. |

The optional media worker processes selected untrusted media. Its isolation and
resource limits do not establish that every decoder issue is unreachable. Review
new stable security updates and rerun the actual image scans before claiming a
clean container result.

## CodeQL review

CodeQL emitted five Actions alerts and twenty source alerts. A successful CodeQL
job means analysis/upload succeeded, not that its results were empty. The table
accounts for every alert in this run; no alerts were dismissed or suppressed.

| Alerts | Review and action |
| --- | --- |
| #1–5: unpinned Docker actions in release workflow | Fixed by replacing the five mutable action references with full commit hashes verified against the same official major tags. Inputs and release behavior are unchanged. |
| #97–98: Capture language flowing into HTML | The initial query/DOM language already passed a supported-language lookup; tested URL payloads did not bypass it. Added explicit URL path encoding and option-value escaping, and applied the same lookup to subsequent language changes. This is boundary hardening, not a claimed demonstrated remote URL exploit. [Browser regression](../../tools/check_capture_language_browser.py) covers seven valid/malformed inputs and a forged DOM change; the previous code fails the forged-change assertion. |
| #81–84: media file path | [Media route](../../tgwitness/app.py) rejects anything except exactly 64 lowercase hexadecimal characters, checks scoped chat access, and rejects symlinks before reading. The reported user input cannot provide path separators through this boundary. Reviewed as guarded input; unchanged. |
| #85–86: locale file paths | [Locale route](../../tgwitness/app.py) and [language selection](../../tgwitness/i18n.py) choose from fixed language lists. The guide-specific file read also checks its list. Reviewed as guarded input; unchanged. |
| #89, #91–95: TData crypto primitives | [TData import](../../tgwitness/tdata.py) implements Telegram Desktop's existing format. SHA-1 and AES block operations form its required key derivation/IGE decryption; the SHA-512 seed feeds PBKDF2. These are not new password-storage choices. Replacing primitives would break import compatibility. Unchanged; legacy-format assumptions remain. |
| #88, #90: synthetic secret/crypto fixtures | [Setup check](../../tools/check_setup_browser.py) writes a fixed synthetic proxy value; [browser fixtures](../../tools/browser_fixtures.py) generate matching synthetic TData. No production credential is read. Reviewed as test fixtures; unchanged. |
| #87: publication scanner logging | [Scanner findings](../../tools/check_publication.py) contain a filename, line and pattern label followed by `value withheld`; matched secret bytes are not interpolated. Reviewed as a false positive; unchanged. |
| #79–80: tag-filter patterns | The [provider-form check](../../tools/check_analysis_settings_browser.py) strips scripts from repository-owned HTML for a fixture. [Diagram parsing](../../tools/site_diagrams.py) recognizes Mermaid arrows and escapes rendered labels; its arrow expression is not an HTML sanitizer. Reviewed as fixture/parser patterns; unchanged. |
| #96: report character range | [Report sanitization](../../tgwitness/report.py) intentionally removes control characters and bidirectional overrides. The flagged range is the intended control range, not an accidental alphabetic range. Unchanged. |

Reviewed false positives remain visible for maintainer review. These conclusions
apply to the cited code and trust boundaries, and should be revisited when those
boundaries change. Follow-up fixes require another CodeQL run; this document does
not predict which alerts that run will close.
