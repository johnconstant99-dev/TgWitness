# Working on TgWitness

Read this file before changing the repository. Use the
[repository guide](docs/AGENT-GUIDE.md) to find the relevant code and documentation,
and follow the [contribution guide](.github/CONTRIBUTING.md).

## Start with the current checkout

- Inspect the branch, `git status --short --branch`, and the relevant diff.
  Preserve uncommitted work from the operator and other sessions.
- Read the implementation and its tests before changing behavior or describing
  a capability. Use `rg` to locate callers, command arguments and fixtures.
- Distinguish work implemented on another branch, merged into `main`, included in
  a release, and shown in a synthetic demo. Record the revision when it matters.
  An old build directory or screenshot does not establish installed behavior.
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

- Write original documentation, interface text and GitHub content in English.
  Keep requested translations aligned with their English source.
- Do not add code comments or docstrings unless the program consumes them,
  such as command help or MCP tool descriptions.
- Preserve verification of existing signed journals and exports. Search,
  display normalization and translation must not rewrite signed payloads.
- Keep received Telegram updates, analytical inferences and unknown facts
  distinct. Missing message IDs or observation gaps do not prove deletion.
- Cloud collection, Takeout, Pseudo-secret and the optional capture components
  have separate capabilities and limits. Check the implementation, branch and
  [qualification record](docs/STATUS.md) before making a support claim.
  A fictional Secret Chat demo is not a live protocol test.
- Keep local signatures, independently retained checkpoints, witness records,
  trusted timestamps and hardware attestation distinct. Explain what each checks.
  A valid signature does not establish the truth of every recorded statement.
- Verify Phala/Intel TDX claims against the actual image, measurements, verifier
  and evidence. Attestation of one component does not attest another recorder.

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
- State which checks ran, where they ran and what remains unverified.
  Passing fixtures do not establish live-service qualification.
- A successful site build is not a confirmed deployment. Inspect the deployment
  result and public artifact before reporting publication.

## Git and delivery

- Push or publish only when the operator requests it. Authorization for one
  publication does not authorize later unrelated pushes.
- Do not force-push, rewrite published history, delete branches or tags,
  or change branch protection.
- Review the staged diff and include only the task's changes.
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
  for status questions; a failed HTTP probe does not prove a VM is off.
- Restore backups only within an authorized restoration task and into a separate
  private destination. Preserve the original archive and key material.
