# Independent verification

[Security policy](../.github/SECURITY.md)

Check the exact file you received against its public workflow and source commit.
GitHub's hosted runners, OIDC and Sigstore supply the provenance records; your
verification policy picks the workflow and code revisions you trust.

For a Telegram archive, start with [sealed evidence](#sealed-evidence), or the
[signed journal guide](wiki/Exports-and-Verification.md) for a local workspace.
For a TgWitness release, follow the source-archive steps below.

## Release source archive

Get a recent [GitHub CLI](https://cli.github.com/manual/gh_attestation_verify). From the
release download `TgWitness-<ver>.zip`, `.zip.sha256`, `sbom.spdx.json`,
`provenance.sigstore.json` and `sbom.sigstore.json`. The ZIP is built by
`tools/build_source.py` on GitHub-hosted Ubuntu (it's separate from the older
`*-source.zip` asset).

Pick the full commit SHA you reviewed, look at `.github/workflows/provenance.yml`, its
pinned actions and `tools/build_source.py` at that commit. Don't take the SHA from an
untrusted archive and don't assume tags never move. Then:

```sh
VERSION='<ver>'
COMMIT='<reviewed-release-commit>'
gh attestation verify "TgWitness-${VERSION}.zip" \
  --repo phishdestroy/TgWitness \
  --signer-workflow phishdestroy/TgWitness/.github/workflows/provenance.yml \
  --signer-digest "$COMMIT" --source-digest "$COMMIT" \
  --source-ref "refs/tags/v${VERSION}" --deny-self-hosted-runners
```

This checks the file digest, the SLSA provenance signature, repository, workflow
revision, source commit/ref and that a hosted runner built it. A checksum alone says
nothing about who built the file. Run it again on `.zip.sha256`. For saved bundles add
`--bundle provenance.sigstore.json`; for offline checks fetch trusted roots beforehand.

Commits were squashed on 3 November 2026. Tags now point to commits with the same
files, but attestations of earlier releases name the original commits, which are still
reachable on GitHub. Use these as `COMMIT`:

| Release | Attested commit |
| --- | --- |
| 0.8.1 | `5ad1569e0b5bc8fce6920b5439eb3e35418a2193` |
| 0.8.0 | `204e31bd294534574a9ef9428f24a38c81b57e6b` |
| 0.7.1 | `99225f985701b0cdccb333d947c6bb9bad8673aa` |

### Rebuilding the source ZIP

`python tools/build_source.py` sorts entries and fixes timestamps, permissions and
compression, so the same input bytes and Python/zlib give the same ZIP. The 1980
timestamp is just a neutral value. To compare with a hosted ZIP, build from the reviewed
commit in a clean checkout with the same line-ending settings and toolchain, then compare
SHA-256. Line endings and compressor versions can change the result.

## Sealed evidence

After decrypting the handoff from [SEALED-ACTIONS](SEALED-ACTIONS.md), verify
`evidence.zip` against your fork (`OWNER/TgWitness`):

```sh
gh attestation verify evidence.zip --bundle attestation.jsonl \
  --repo OWNER/TgWitness \
  --signer-workflow phishdestroy/TgWitness/.github/workflows/sealed-collector.yml \
  --signer-digest 6816bfba2622c2446a7cf2ab8d7a6cd061c31f02 \
  --deny-self-hosted-runners
```

Review the [pinned collector workflow](https://github.com/phishdestroy/TgWitness/blob/6816bfba2622c2446a7cf2ab8d7a6cd061c31f02/.github/workflows/sealed-collector.yml),
which checks out collector commit `5bd1343faad4d6b248171d90ecb540cea589bfbf`.
For journal, attachment, policy and coverage checks also run the verifier from an
installation you trust:

```sh
python -m tgwitness.sealed_verify evidence.zip --bundle attestation.jsonl --repo OWNER/TgWitness
```

## Public records and SBOM

- **Transparency log.** The attestation step's Actions summary links to Rekor; the bundle's
  `verificationMaterial.tlogEntries` has the log entry and inclusion proof. Browse it on
  [Sigstore search](https://search.sigstore.dev/). A log entry timestamps a commitment,
  not Telegram messages ([Rekor](https://docs.sigstore.dev/logging/overview/)).
- **Scorecard.** [OpenSSF Scorecard report](https://securityscorecards.dev/viewer/?uri=github.com/phishdestroy/TgWitness),
  runs every Monday and on pushes to `main`. Look at the date, commit and findings, not just
  the score. It's automated, not a human audit.
- **Workflow audit.** [workflow-audit.yml](../.github/workflows/workflow-audit.yml) runs zizmor
  on workflow changes and every Monday, results in the `workflow-audit-sarif` artifact.
- **Dependencies.** `sbom.spdx.json` combines what Syft finds with the exact Python versions
  from `deploy/requirements.lock`, `deploy/build.lock` and `deploy/constraints-mcp.txt`.
  The workflow fails on missing, extra or mismatched packages.

  Verify the SBOM signature with the release command above (`sbom.spdx.json` as the file),
  and its binding to the source ZIP:

  ```sh
  gh attestation verify "TgWitness-${VERSION}.zip" \
    --bundle sbom.sigstore.json \
    --predicate-type https://spdx.dev/Document/v2.3 \
    --repo phishdestroy/TgWitness \
    --signer-workflow phishdestroy/TgWitness/.github/workflows/provenance.yml \
    --signer-digest "$COMMIT" --source-digest "$COMMIT" \
    --source-ref "refs/tags/v${VERSION}" --deny-self-hosted-runners
  ```

  Then scan it locally:

  ```sh
  grype sbom:sbom.spdx.json
  ```

## What this doesn't guarantee

- No bugs, no malicious behavior, no vulnerable deps, or that GitHub, Sigstore, the pinned
  actions or your tools weren't compromised.
- That Telegram content is authentic, true or complete, that unseen deletions come back,
  or that the capture host can't read it.
- Anything about portable ZIPs, wheels, containers, GitHub's automatic source downloads,
  old `*-source.zip` files or releases without this attestation.
- Reproducible builds of full releases, containers, wheels or SBOMs.
- A complete list of installed or OS packages, or that they're free of vulnerabilities.
