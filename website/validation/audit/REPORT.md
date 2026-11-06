**TgWitness · Release audit**  
6 November 2026 · UTC · v0.9.1 · revision `92e539af40d8`

**Status: completed with open findings.** The published build passed the checks below and was installed on all three servers. All 221 checked identity and key files retained their original hashes. The unpublished secret chat module has three reproduced defects; 16 fleet profiles remain unverified in Telegram because their WARP routes failed qualification.

| Build | Verified release |
|---|---|
| Source | `92e539af40d8368d198ff5e040f1d876f2c1310e` |
| Release | `92e539af40d8-83e41104669e` |
| Deployment | 3 servers; installed-package smoke checks passed on each |
| Final state | Audit processes stopped; the third panel listens on loopback with no Telegram connections; its normal route helpers remain running |

**Live export performance**

Fresh text and metadata exports through WARP, with two accounts per server. Attachments and avatars were excluded.

| Server | Records | Acquisition | Complete cycle | Records/s, complete cycle |
|---|---:|---:|---:|---:|
| A | 27,030 | 189.043 s | 211.647 s | **127.713** |
| B | 29,299 | 182.513 s | 206.650 s | **141.781** |

Both jobs started without resume and finished with **zero duplicate or reused records**. WARP was confirmed before each Telegram connection. Archive signatures were verified against previously retained key fingerprints. The Python socket guard recorded no direct connection attempts; this was not a host firewall audit.

Complete-cycle timing uses a monotonic clock and includes preparation, acquisition, selection, packaging and archive verification. Saved pacing and FloodWait delays were respected: four events on A and three on B. Server A also ran the protected-chat check during its measurement. These are two observed workloads, not a general throughput guarantee.

**Validation coverage**

| Area | Result | Scope or remaining limit |
|---|---|---|
| Core pytest | **1,461 passed** | 37 platform skips; no unresolved failures in the executed cases |
| Browser / browser UX / evidence / site | **102 / 66 / 15 / 9 passed** | Check programs overlap pytest cases; do not add the counts as unique tests |
| Additional checks | **13 passed** | One module was rerun with the correct pytest invocation |
| Capture addon | **124 passed** | 3 Official Web checks blocked by the required Chromium sandbox |
| API authorization | **269 routes, 538 requests passed** | Requests without credentials or with revoked access |
| Retained archives | **48 of 48 verified** | 3,598,381 records checked with the current verifier and pinned keys |
| Runtime dependencies | **47 pinned packages; no known advisories found** | Advisory result as of this audit; lint and publication checks also passed |
| Fleet profiles | **24 of 40 passed live read checks** | 16 WARP routes failed qualification; those profiles were not connected to Telegram |

The initial 19 pytest failures were resolved by installing Chromium and CJK fonts and building the site. Browser checks that timed out with the test environment on a network volume completed after retesting on local storage; original results were retained. The 37 skips comprise 32 Windows cases and five cases requiring a specific Linux container. CI for this exact revision separately passed Linux/Windows installer, Docker/Compose and OCR/ASR checks; that does not validate every skipped case. [Checks](https://github.com/phishdestroy/TgWitness/actions/runs/42263850905) · [Installer](https://github.com/phishdestroy/TgWitness/actions/runs/42263850962)

Live account checks covered expected identity, authorization, deletion/restriction/frozen flags and a five-dialog sample. They do not establish that every outgoing action is unrestricted. Another 13 credential-bearing profiles on the third server were preserved but were not checked live.

**Protected content and local performance**

| Check | Observation |
|---|---|
| Protected public chat | All **21,393 message numbers** in the prior bounded range queried; **2,454 records** recovered, matching the prior archive |
| Comparison | **0 missing, added, duplicate or changed core records** within that range |
| Synthetic ingestion | 5,000 messages across 100 chats in 16.897 s: **295.9 events/s** |
| Synthetic handler latency | p50 **2.689 ms**; p95 **6.963 ms** |
| Synthetic export | 13.07 s with tracemalloc enabled; 107.56 MiB peak traced Python allocation, not process RSS |
| Deployed panel API | Three sequential loopback requests to `/api/profiles`: **9.9 / 8.6 / 23.1 ms**, HTTP 200; 14 profiles and no Telegram connections |

The protected source had Telegram's `noforwards` flag. This was an exhaustive functional read of its bounded ID range, not an isolated speed test or an E2E secret chat test. An empty Telegram response alone does not prove deletion. The synthetic workload used no network or media downloads and verified 5,001 journal events: 5,000 messages plus one actor refresh event. Panel readiness responded in 11.6 ms; browser rendering and external network latency were outside that measurement.

**Open findings**

| Priority | Finding | Evidence and disposition |
|---|---|---|
| **P1** | Secret chat close bypasses `read_only` | `tgwitness/secret_chats.py:303`: expected 0 remote actions, observed 1 through a mocked manager. Open. |
| **P2** | Secret chat replay can duplicate older records | `secret_chats.py:153`: deduplication searches only 500 events. Replaying an older message after 502 records and a simulated restart produced record 503. Open. |
| **P2** | Secret attachment retry is lost | `secret_chats.py:247`: a transient download failure removes the pending job. Open. |
| **P2** | Official Web cannot use its required sandbox | Three addon checks fail at browser startup in the current RunPod containers. The sandbox remains enabled. Open. |
| **P2** | 16 fleet profiles lack qualified WARP routes | Helper registration failed. This does not establish that the Telegram accounts themselves are faulty. Live checks remain open. |
| **P3** | Capacity harness expects the wrong event total | `tools/check_capacity.py:61` expects 5,000 events instead of 5,001. Only the private measurement harness was adjusted; the exact message count was checked separately. Repository assertion remains unchanged. |

The secret chat module is **absent from the audited published main and installed build**. Its findings apply to unpublished snapshot `bb8788fb685c`, tested with a synthetic store and mocked Telegram manager. No real secret chats or messages were created. Fix these defects before enabling that module. The audited file's SHA-256, with Windows line endings, is `d03cb3f02908b48787496e8a36fe8bf78fc8d38a9efe71bf88d7feee958940c7`; the Git blob hash is also recorded in `PROOF.json`.

Interactions, imports, recovery, media, integrations and permission boundaries were primarily tested with synthetic inputs. This audit does not claim live coverage of every feature or external service.

**Evidence, privacy and verification**

The 1,487 source files matched the pinned Git tree after applying its declared line-ending rules. The largest file was 2,205,229 bytes; none exceeded 5 MiB. The publication scan found no recognized secret formats. This is a bounded format scan, not an exhaustive guarantee about every possible form of personal data.

The package contains this report, aggregate measurements, a signed statement, a verifier and file checksums. It excludes message bodies, source names, Telegram account identifiers, IP addresses, session material, account keys and raw logs. Private archives and detailed receipts remain on the owner's servers.

The dedicated audit key authenticates the report's contents. These are operator measurements, not independent attestation, proof of Telegram authorship or GDPR certification. The audit made no repository edits, commits or public uploads.

To verify the report signature and included file hashes, run the following from the extracted folder in a Python environment with `cryptography` installed:

```text
python VERIFY.py --key-sha256 e419743db20096763ea06e480c2e6c161341de2f1023cd339c77758fb69e212f
```

