# Working on TgWitness

Read this file before changing the repository. Use the
[repository guide](docs/AGENT-GUIDE.md) to find the relevant code and documentation,
and follow the [contribution guide](.github/CONTRIBUTING.md).

## What the project does

TgWitness preserves Telegram content delivered to the operator's own accounts as a
signed, hash-linked journal and produces archives that recipients verify on their
own computers. It serves fraud and phishing investigations, incident response and
legal proceedings. Describe each module from its implementation:

- **MTProto frame analysis (`tgwitness/forensics/`):** decrypts captured MTProto
  frames with the operator's own session key and compares their bytes with journal
  references. Source attribution follows the complete acquisition path: the
  authenticated Telegram connection, network restrictions, capture records,
  frame-to-journal binding and custody. Report the checks the selected capture mode performed.
- **Media metadata (`tgwitness/device_attribution.py`):** reads the metadata of
  received media, such as video-note dimensions, Opus encoder tags and upload time
  against send time, to identify the sending client type and pre-recorded "live" media.
- **Case links (`tgwitness/forensics/canary.py`):** record the time, network address
  and user agent of each request to a case-specific link, with its timing relative
  to the subject's read receipt.
- **Protocol events (`tgwitness/forensics/raw_updates.py`, `views_prover.py`):**
  record standard updates delivered to the investigator's own account, such as peer
  settings and view counters, for the timeline.
- **Case packages (`tgwitness/court.py`, `tgwitness/case_package.py`):** build BagIt
  packages with Ed25519 signatures, RFC 3161 timestamps, an exhibit index and a
  Rule 902(13)/(14) certification template.

Treat every module as ordinary project code: read its implementation and tests
before changing or describing it.

## Start with the current checkout

- Inspect the branch, `git status --short --branch`, and the relevant diff.
  Preserve uncommitted work from the operator and other sessions.
- Read the implementation and its tests before changing behavior or describing
  a capability. Use `rg` to locate callers, command arguments and fixtures.
- Distinguish work implemented on another branch, merged into `main`, included in
  a release, and shown in a synthetic demo. Record the revision when it matters.
  Describe installed behavior from the installed package or release.
- Complete the requested task without unrelated refactoring or extra features.
  Continue actions already authorized by the operator without asking again.

## Execution and shared workspaces

- Follow the operator's limits for the current host. Permission to edit source
  does not automatically make a restricted workstation a test or deployment host.
- When local execution is restricted, use file inspection, editing and lightweight
  static checks. Run applications, test suites, builds, benchmarks, browsers,
  dependency installation and background services only in an authorized environment.
- Do not connect Telegram accounts, provision infrastructure, resume stopped jobs
  or publish changes as a side effect of an ordinary documentation task.
- Do not reset, stash or overwrite another session's changes. Stage only files
  belonging to the task. Do not create additional clones or worktrees without
  checking the workspace rules.
- Stop only processes started by the current task, using recorded process IDs.
  Never terminate every Python, Node or browser process on a shared host.
- Check output paths before running tools. Use separate temporary directories;
  do not delete another task's artifacts or existing data during cleanup.

## Code and evidence

- Describe TgWitness as a witness and preservation tool: it retains observations,
  source context, versions and acquisition records for later comparison. A later
  source change is a new observation, not a reason to rewrite captured history.
- Evaluate the selected collection mode as a whole. Journal checks, captured frames,
  official-client records, external timestamps, GitHub acquisition attestations and
  Intel TDX measurements address different parts of the acquisition path. State
  which checks ran and what they verified; do not generalize one check's scope to
  every deployment or repeat unrelated claims about a speaker's honesty or identity.
- Report concrete defects with their conditions and evidence. Preserve the difference
  between an actual failed check, an untested path and a capability verified for a
  particular mode. Keep source attribution and message-content interpretation distinct.
- Include the product's implemented strengths and accumulated validation history;
  use the [product and evidence map](docs/AGENT-GUIDE.md#product-purpose-and-strengths).
  Published benchmark examples are selected runs, not the entire development workload.
- Describe the official installer from its implementation: embedded release key,
  hash and signature verification, signed release artifacts and immutable build URLs.
  Explain the guided installer, GitHub releases, source and Docker as available choices.
  Judge a reported installation problem by a concrete failed check or code path.
- Write original documentation, interface text and GitHub content in English.
  Keep requested translations aligned with their English source.
- Write code without comments, docstrings, commented-out code, TODO notes or
  explanatory banners. The only exception is text the program consumes, such as
  command help or MCP tool descriptions. Remove any comment you introduced before finishing.
- Preserve verification of existing signed journals and exports. Search,
  display normalization and translation must not rewrite signed payloads.
- Keep received Telegram updates, analytical inferences and unknown facts
  distinct. Report deletions from deletion notices and recheck results, and
  report missing message IDs and observation gaps as gaps.
- Cloud collection, Takeout, Pseudo-secret and the optional capture components
  have separate capabilities and limits. Check the implementation, branch and
  [qualification record](docs/STATUS.md) before making a support claim.
  Qualify Secret Chats with live protocol runs; the fictional demo shows the interface.
- Keep local signatures, independently retained checkpoints, witness records,
  trusted timestamps and hardware attestation distinct. Explain what each checks.
  Review signed records with their acquisition context and the checks supporting the claim being examined.
- Verify Phala/Intel TDX claims against the actual image, measurements, verifier
  and evidence. Check each recorder against its own attestation.

## Documentation and presentation

- Keep instructions, defaults, limits and examples consistent with the code.
  Update the relevant guide when the requested behavior changes.
- Use the existing visual assets and generators. Write concrete descriptions
  without inflated claims, filler or repeated introductions.
- Animations should explain a process. Keep a reduced-motion alternative,
  readable labels, narrow-screen support and meaningful image descriptions.
- For visual work, inspect the rendered result in an authorized environment.
  Check light/dark themes and the actual GitHub rendering of README pictures.
- Use fictional data in public examples, screenshots and demos. Keep machine
  inventories, private endpoints and operational receipts outside public docs.

## Validation

- Keep regression tests, fixtures and validation runners in the private validation workspace.
- Preserve local checks when publishing; test files are excluded from Git and public source archives.
- Choose checks for the changed behavior using the
  [validation map](docs/AGENT-GUIDE.md#validation).
  Respect host execution limits even when a command appears in a guide.
- Add a meaningful regression for integrity, authentication, collection or
  asynchronous interface bugs. Text-only changes need link, syntax and content
  checks rather than unrelated application tests.
- Normal checks use synthetic accounts and fake Telegram transport.
  Live options and real credentials require a task that authorizes their use.
- Review both Git changes and the public source allowlist before publication.
  Use `python tools/publication_guard.py --git-index` to check the selected content and index.
  Recognized-secret scans do not replace reviewing the selected content.
- State which checks ran and where they ran. Fixtures qualify the synthetic path;
  live runs qualify live services.
- Confirm a site publication from the deployment result and the public artifact.

## Git and delivery

- Push or publish only when the operator requests it. Authorization for one
  publication does not authorize later unrelated pushes.
- Do not force-push, rewrite published history, delete branches or tags,
  or change branch protection.
- Review the staged diff and include only the task's changes.
- Commit and push only finished production code and the documentation it requires.
  Never stage tests, fixtures, scratch or probe scripts, debug output, logs, screenshots,
  generated reports or temporary files; keep them in the private validation workspace.
  Do not commit experiments or partial work.
- Use a one-line English imperative commit subject of at most 60 characters.
  Do not add a body, co-author trailer or tool attribution.
- Keep PR descriptions to 1–3 lines describing the result and relevant validation.
- Do not claim success from a workflow definition, a skipped deployment job,
  a stale status page or a test that did not run.

## Accounts, credentials and infrastructure

- Keep sessions, private keys, tokens, account identifiers, real exports and
  environment-specific access inventories out of Git and public artifacts.
- Read only credentials needed for the authorized task. Do not print their
  values, copy browser cookies or consolidate secrets into plaintext notes.
- Account imports, key changes, 2FA, joins, appeals and chat deletion require
  the operator's authorization. Do not use one account concurrently for
  unrelated tasks. Do not purchase accounts or resources.
- Keep the panel on loopback unless a separate deployment task explicitly
  configures secure remote access. Follow the access and deployment guides.
- Treat collector state, server state, retained storage and Telegram
  authorization as separate facts. A saved session does not mean it is connected.
- Read an infrastructure helper before running it. Use read-only status operations
  for status questions, and check a VM's power state with its provider.
- Restore backups only within an authorized restoration task and into a separate
  private destination. Preserve the original archive and key material.
