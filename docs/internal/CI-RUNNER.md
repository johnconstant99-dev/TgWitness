# CI runner operations

TgWitness's routine checks use a dedicated Ubuntu 24.04 machine registered to this
repository with the labels `self-hosted`, `Linux`, `X64`, and `tgwitness-ci`.
GitHub stores the workflow definitions, job results and logs. The runner executes
the jobs. No collecting Telegram account or production evidence belongs on it.

## What runs and when

| Workflow | Automatic trigger | Execution |
| --- | --- | --- |
| Checks | Program, tooling or deployment changes pushed to `main` | Linux, Python 3.12 package readiness, dependency audit, browser checks, source and Docker validation |
| Project website | Website and documentation inputs pushed to `main` | Build and browser checks on the Linux runner |
| Wiki bundle | Handbook inputs pushed to `main` | Build the downloadable Wiki bundle on the Linux runner |
| Release packages | A published release | Full compatibility checks, release downloads and container publication |

Changes confined to README or prose do not trigger all application checks.
A newer automatic run replaces an outdated run for the same branch.
Each allocated job has a timeout and its own Python virtual environment.
The runner accepts one job at a time, so independent workflows can queue.

In **Actions → Checks → Run workflow**, leave **full_platforms** unchecked for the
normal Linux checks. Checking it also verifies package installation and readiness
with Python 3.11–3.13 across Linux, Windows and macOS and builds Windows portable. Windows/macOS use GitHub-hosted
runners and consume the account's included compute while this repository is private.
Published releases explicitly request this complete matrix.

Source ZIPs are uploaded for manually requested checks or full release checks.
Routine dependency reports and Wiki bundles expire after three days. The website
artifact is uploaded only for Actions deployment or a manual website run and
expires after one day. GitHub artifact storage has its own allowance even when
compute runs on a self-hosted machine.

## Prepare a replacement host

Use an otherwise empty Ubuntu 24.04 server. Four CPU cores, 8 GB RAM and at least
40 GB of available disk are a practical starting point. The administrator needs
SSH access. Jobs require outbound HTTPS and package-registry access; the runner
does not need an inbound public web endpoint.

1. Copy a full checkout of the reviewed repository revision onto the host,
   including [`deploy/site.lock`](../../deploy/site.lock). Run
   [`scripts/install-ci-runner.sh`](../../scripts/install-ci-runner.sh) as root. It installs
   Docker, Python, browser libraries and a checksum-verified runner release.
2. In **Settings → Actions → Runners → New self-hosted runner**, select Linux x64
   and obtain a short-lived registration token. Keep the account API token off
   the server; registration needs only this temporary token.
3. Register with a unique host name and the existing routing label:

```bash
cd /opt/actions-runner
read -r -s -p 'Registration token: ' runner_token
printf '\n'
sudo -u gha ./config.sh --unattended \
  --url https://github.com/phishdestroy/TgWitness \
  --name tgwitness-ci-replacement --labels tgwitness-ci \
  --work _work --token "$runner_token"
unset runner_token
./svc.sh install gha
./svc.sh start
```

The `gha` service account owns the runner and belongs to the Docker group.
Docker access is powerful; keep this machine dedicated to CI. The runner updates
itself automatically. OS and Docker updates remain the host administrator's job.
The installer is repeatable and leaves an existing runner registration intact.

## Verify and transfer

- Confirm the new runner is **Idle** in repository settings.
- Start **Checks** manually with **full_platforms** unchecked. Confirm the jobs
  identify the new host and finish successfully.
- Stop the old runner service and remove its registration from GitHub. Remove
  the old VM at the provider after verifying the replacement. A powered-off VM
  may still incur provider charges.
- If the old host failed during a job, re-run that job. Source code and committed
  configuration remain in GitHub; caches can be recreated.

This setup does not automatically run pull-request workflows. Review changes
before putting them on `main` or dispatching a workflow. Before making the
repository public, review runner access and outside-contributor approval rules;
do not run untrusted fork code on this persistent host.

## Diagnose an offline runner

```bash
cd /opt/actions-runner
sudo ./svc.sh status
df -h
docker system df
```

Inspect the runner's `_diag` directory and its systemd service journal. Do not
publish `.credentials`, `.credentials_rsaparams`, SSH private keys or provider
API tokens. If the machine is gone, provision a replacement using the same
`tgwitness-ci` label. New queued work can then be assigned to it.

Provider promotional credit and expiry are account-specific. Record them in the
private infrastructure inventory and review them before the trial ends. Stopping
the runner service does not terminate the underlying server subscription.
