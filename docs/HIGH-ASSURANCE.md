**English** · [Русский](ru/HIGH-ASSURANCE.md)

# High-assurance deployment

A signed journal proves that records were not changed **after** signing. For serious cases
the next question is whether anyone could have shaped the data **before** it was signed:
who ran the collector, on which machine, and whether someone logged in to it. This optional
mode deploys the collector so that a third party can check that, using records kept by the
cloud provider and Cloudflare rather than the operator's word.

Ordinary local and Docker use is unchanged. Nothing here runs unless you deploy with
`python -m tgwitness.cloud`, and the collector reads its host only when the deployment sets
`TGWITNESS_ASSURANCE`.

```mermaid
flowchart LR
    O[Operator] -- provider API --> P[Server, firewall without inbound rules]
    O -- Cloudflare API --> T[Tunnel and DNS]
    P -- outbound only --> T
    P --> K[Signing key created on the server]
    V[Verifier, read-only tokens] --> PL[Provider log and firewall]
    V --> CF[Tunnel connector address and ingress]
    V --> S[Signed /api/assurance statement]
    V --> J[Evidence ZIP]
```

## What a verifier can check

| Claim | How it is checked | Kept by |
| --- | --- | --- |
| The server was created through the provider API at a known time | Server object and its creation in the provider's own log | Provider |
| Nobody used the provider's access paths | Log of console requests, rescue, password reset, rebuild, ISO, images, backups | Provider |
| Nothing could connect to it | The provider firewall has no inbound rules; SSH is masked from the first boot | Provider (firewall), host (SSH) |
| The panel is reached only through the tunnel | Tunnel ingress forwards to the panel alone; the connector runs from the server's address | Cloudflare |
| This exact software runs | The collector's signed source-tree hash equals a checkout of the deployed commit | Collector, checked against Git |
| The signing key was created on that server | The key signs a statement naming the provider's server ID and the hash of the cloud-init it received | Collector, checked against the provider |
| The journal belongs to that key and server | Every process start in the evidence ZIP carries the host measurement for that server | Evidence ZIP |

Host measurements (SSH listeners and processes, current sessions, logins in `wtmp`, the boot)
are reported by the collector itself and are signed into every process start and into
`host.state` records whenever they change. Root on the server could falsify them; they
support the provider and Cloudflare records rather than replace them.

## Providers

| `--provider` | Credentials | Verifier's read-only access | Provider log for the verifier | Kept for |
| --- | --- | --- | --- | --- |
| `hetzner` | `HCLOUD_TOKEN` | Read token of the same project | Server and firewall actions | While the resources exist |
| `digitalocean` | `DIGITALOCEAN_TOKEN` | Read-only personal access token | Droplet actions | While the Droplet exists |
| `linode` | `LINODE_TOKEN` | `linodes`, `firewall`, `events` read-only scopes | Account events, firewall rule versions | 90 days |
| `vultr` | `VULTR_API_KEY` | User with read access and the `activity_logs` permission | Account activity log (method, path, actor) | 30 days, longer with an audit-log subscription |
| `aws` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | `ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`, `cloudtrail:LookupEvents` | CloudTrail event history | 90 days |
| `phala` | `PHALA_CLOUD_API_KEY` | An API key of the same workspace | Application revisions: compose and environment changes, restarts, OS upgrades | While the application exists |
| `generic` | none | none | none: **self-attested** | – |

Use a dedicated project, team, account or sub-account for each case: the verifier's
read-only access then shows only this deployment. Credentials are read from
`--provider-token-file` or the variable above, never from the command line. For AWS the file
holds `ACCESS_KEY_ID SECRET_ACCESS_KEY [SESSION_TOKEN]`; the region is `--location`.

What each provider's records cannot show is printed in every report. In short: Hetzner
logs console requests; DigitalOcean's Recovery Console, Linode's Lish/Glish and Vultr's web
console are not logged as such, so root is locked at the first boot and a console login
would need a password reset or a boot change, which are logged. Vultr returns the console
address to any key that can read the instance; neither the record nor the report stores it.

## Confidential VM on Phala Cloud (Intel TDX)

With `--provider phala` the collector runs in an Intel TDX confidential virtual machine on
[Phala Cloud](https://phala.com/), managed by dstack. The host and Phala's staff cannot read its
memory, and the processor signs an attestation of what the machine booted. The verifier does not
take Phala's word for it: `tgwitness.tdx` checks every attestation itself, up to the pinned Intel
SGX Root CA, against Intel's revocation lists and Intel's signed platform data, and refuses
machines that can be debugged or migrated.

| Report entry | What it shows |
| --- | --- |
| `tdx_binding` | The attestation covers the signed statement of the collector and the random value of this request |
| `tdx_quote` | Intel vouches for the attestation; it passes only when Intel rates the platform as up to date |
| `tdx_compose_hash` | RTMR3, replayed from the dstack event log, measures the app-compose the collector reports |
| `tdx_compose` | That compose is byte for byte the one the code of the deployed commit builds: source files pinned by hash, both images by digest, no other code |
| `tdx_identity` | The attestation comes from the deployed application and instance, with keys from Phala's KMS and an encrypted disk |
| `tdx_os` | With `--tdx-measurements`, MRTD and RTMR0-2 equal the values computed from the dstack OS image (`dstack-mr measure --json`) |

Every start of the collector recorded in the journal carries such an attestation, so
`verify --evidence` checks each start. Phala's list of application revisions serves as the
provider log: if the compose changed after the deployment, the report fails.

In the panel choose **Confidential virtual machine · Phala Cloud** under **Extras** → **Server 24/7**
and paste a Phala Cloud API key; the quick tunnel works as on Hetzner. From the command line:

```sh
python -m tgwitness.cloud deploy --provider phala --name case-1 --server-type tdx.small \
    --ref v0.8.0 --repository https://github.com/phishdestroy/TgWitness --quick-tunnel \
    --provider-token-file phala-key.txt
python -m tgwitness.cloud verify --record deployments/case-1/deployment.json \
    --provider-token-file phala-key.txt --cloud-init deployments/case-1/docker-compose.yaml \
    --source CHECKOUT_OF_COMMIT --tdx-measurements dstack-mr.json
```

`--tdx-collateral` reads Intel's certificates and revocation lists from a file instead of
downloading them from Intel. Gateway DNS is not available here: Phala has no provider firewall
for outgoing traffic.

An attestation cannot rule out a flaw in Intel's TDX module or microcode, or physical access to
the memory bus. Whoever controls the application in Phala's account can deploy another compose;
it appears as a new revision with a new compose hash. The host controls the machine's time
source and network.

## Before you start

1. A Cloudflare zone, its account ID, and an API token with **Cloudflare Tunnel Edit**,
   **Zone Read** and **DNS Edit**, given with `--cloudflare-token-file` or
   `CLOUDFLARE_API_TOKEN`. For the verifier: **Cloudflare Tunnel Read**, **DNS Read** and, for
   the audit log, **Account Settings Read**. Without a domain, a
   [quick tunnel](#quick-tunnel-without-a-domain) needs none of this.
2. Provider credentials with write access to a dedicated project; `lock` uses the same:
   - Hetzner: API token with Read & Write permission;
   - DigitalOcean: personal access token with write access;
   - Linode: personal access token with `linodes`, `firewall` and `events` read/write scopes;
   - Vultr: API key of a dedicated account or sub-account;
   - AWS: IAM credentials allowed `ec2:DescribeVpcs`, `ec2:DescribeImages`,
     `ec2:CreateSecurityGroup`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:RunInstances`,
     `ec2:CreateTags`, `ec2:DescribeInstances`, `ec2:DescribeSecurityGroupRules` and
     `ec2:RevokeSecurityGroupIngress`.
3. The commit to run. A release tag is resolved once to its commit with `git ls-remote`;
   the server only ever receives the 40-character commit.

## From the panel

On your own computer, **Extras → Server 24/7** runs the same `deploy` for Hetzner in three
steps: choose Europe or the United States, paste a Hetzner token (Read & Write), then review
the server type, monthly price, address and version the panel found with that token. Nothing
is created before you confirm. The panel shows each step as `deploy` reports it, then the
address, the panel token and the signing key fingerprint. Without a domain the server gets a
[quick tunnel](#quick-tunnel-without-a-domain); **Your servers → Find the current address**
looks it up again after a restart. For a fixed address under your own domain, open
**Optional · your own domain** and add a Cloudflare token (the prepared link selects Zone
Read, DNS Edit and Cloudflare Tunnel Edit).

The tokens travel with each request from the browser tab to TgWitness on the same computer
and are not written anywhere; the deployment record, redacted cloud-init, panel token and,
for a quick tunnel, the address key are kept in `deployments/NAME` inside the data directory.
The panel offers this only to the main administrator on a direct loopback connection
(`127.0.0.1`, no proxy or tunnel headers); a panel reached over a network shows the commands
instead. The version defaults to the release tag of the running panel, resolved through the
GitHub API. Location, server type and price come from Hetzner's API: `cpx22` where it is
offered, otherwise the cheapest x86 type with at least 2 GB of memory.

## Quick tunnel without a domain

`--quick-tunnel` replaces `--zone`, `--cloudflare-account` and `--panel-host`; no Cloudflare
account or token is involved:

```sh
python -m tgwitness.cloud deploy --provider hetzner --name case-2026-11 --server-type cpx22 \
    --ref 0123456789abcdef0123456789abcdef01234567 --quick-tunnel --provider-token-file hetzner.token
```

On the server, cloudflared opens a
[quick tunnel](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)
to the panel: a random `https://….trycloudflare.com` address that changes whenever cloudflared
or the server restarts. A small service on the server posts each address to a random ntfy.sh
topic, signed (HMAC-SHA256) with a key only the deployment directory holds
(`address-key.txt`), and repeats it every three hours because ntfy.sh keeps posts for 12.
`deploy` and **Find the current address** accept signed posts only, so a forged post cannot
send you, and your panel token, to someone else's address. The topic is in the record and the
published cloud-init: whoever has them can read the current address, which still asks for the
panel token. The server keeps no inbound port either way.

What it costs: no Cloudflare account keeps records of a quick tunnel, so `verify` reports the
tunnel, connector and DNS check as unavailable and the result is at best `incomplete`; the
provider records, firewall, signed statement, host measurements and installer comparison are
checked as usual. The byte comparison with the reference installer needs a deployed commit
that already knows `--quick-tunnel`; a 0.7.0 checkout builds the domain installer and reports
the difference. Cloudflare gives quick tunnels no uptime guarantee, allows 200 requests in
flight and does not carry Server-Sent Events, so the panel's live updates (versions after 0.7.0)
may not arrive through one and a view needs reloading; that part has not been tried. For a case
that has to stand, use your own domain.

## Deploy

Look at everything that will be sent first. `plan` makes no provider or Cloudflare request:

```sh
python -m tgwitness.cloud plan --provider hetzner --name case-2026-11 --server-type cpx22 \
    --ref 0123456789abcdef0123456789abcdef01234567 --zone example.org \
    --cloudflare-account CLOUDFLARE_ACCOUNT_ID --panel-host case.example.org
```

Then deploy with the same options and the credentials:

```sh
python -m tgwitness.cloud deploy --provider hetzner --name case-2026-11 --server-type cpx22 \
    --ref 0123456789abcdef0123456789abcdef01234567 --zone example.org \
    --cloudflare-account CLOUDFLARE_ACCOUNT_ID --panel-host case.example.org \
    --witness-host case-witness.example.org \
    --provider-token-file hetzner.token --cloudflare-token-file cloudflare.token
```

Server types to start with: `cpx22` (Hetzner), `s-1vcpu-2gb` (DigitalOcean), `g6-standard-1`
(Linode), `vc2-1c-2gb` (Vultr), `t3.small` (AWS). `--location` and `--image` default to each
provider's Ubuntu 24.04 in a European region.

`--repository` takes the commit from another https Git repository, without credentials in the
URL (default `https://github.com/phishdestroy/TgWitness.git`). `deploy` also accepts `--out`
for another deployment directory (default `deployments/NAME`; a directory that already holds a
deployment is refused) and `--wait`, the minutes to wait for the collector's signed statement:
1 to 240, default 20, or 60 for `generic`.

The command:

1. creates a Cloudflare tunnel whose ingress forwards the panel hostname to the panel and,
   if given, the witness hostname to `/api/witness/head` and `/api/assurance` only;
2. creates proxied CNAME records for those hostnames, refusing names that already exist;
3. creates a provider firewall without inbound rules and a server behind it with no SSH key,
   no backups, no console agent, and cloud-init that masks SSH, locks root, installs
   `cloudflared`, fetches exactly the commit, checks it and starts TgWitness as a
   hardened systemd service;
4. waits for the collector's signed statement and checks that it names this server and the
   hash of this cloud-init.

`deployments/case-2026-11/` then holds:

| File | Contents | Share? |
| --- | --- | --- |
| `deployment.json` | IDs, hashes, the API calls made (method, path, status) and the first signed statement | Yes, with the verifier |
| `cloud-init.redacted.yaml` | The exact cloud-init with its two secrets replaced by `REDACTED` | Yes |
| `panel-token.txt` | The panel token | No |

The provider's root password, the tunnel token and the panel token are never written to
`deployment.json`. Publish the collector fingerprint printed at the end through a channel
you do not control alone, for example a witness channel or a message to the recipient.

Sign in to Telegram at `https://case.example.org` with the panel token, as in the
[account guide](ACCOUNTS.md). Panel actions are recorded in the signed journal; they are not
SSH sessions. A [witness](WITNESS.md) can poll `https://case-witness.example.org`.

There is no SSH: if the bootstrap fails, the collector never answers. Delete the server and
deploy again, or use a debug deployment to find the cause.

### Secrets in the user data

The cloud-init carries two secrets: the panel token and the Cloudflare tunnel token. The
signing key is not among them; it is created on the server. Hetzner, DigitalOcean and Linode
do not return user data through their API. Vultr returns it to any key that can read the
instance, and EC2 through `DescribeInstanceAttribute`. For AWS give the verifier only the three
actions in the table, never `ec2:Describe*`. For Vultr, assume the verifier's key can read both
tokens. A tunnel token lets someone run a second connector: `verify` reports any connector
not on the server, and the collector's statements cannot be forged that way because each one
signs a fresh challenge. With `--quick-tunnel` the second secret is the address key instead:
whoever reads it can post a false address that the panel would accept.

The collector's public statement leaves out the server's address and the sources of logins;
both stay in the signed journal.

## Debug deployment and lock

`--debug-ssh-key KEY --debug-ssh-from 198.51.100.4` keeps SSH for one key from one address
or small network, at most a /24 for IPv4 or a /48 for IPv6. `KEY` is already registered with
the provider: the name or ID of an SSH key in the Hetzner project, the ID or fingerprint of an
SSH key in the DigitalOcean team, a Linode username whose profile SSH keys are added to root,
the ID of an SSH key in the Vultr account, or the name of an EC2 key pair in the region. These
options do not apply to `generic`. Such a deployment is recorded as `debug` and is **never** reported as
high-assurance. When you are done, run `sudo tgwitness-lock` as the last command of the last
SSH session, then:

```sh
python -m tgwitness.cloud lock --record deployments/case-2026-11/deployment.json --provider-token-file hetzner.token
```

The firewall loses every inbound rule. Reports then show when SSH was allowed and when it
was closed; that window stays visible.

## Remove a deployment

`destroy` deletes the server and its firewall, found by the deployment's label so that a
deployment which failed half-way is removed as well, then the DNS records that point to its
tunnel, and the tunnel. The server's journal and signing key are deleted with it: export the
evidence first. The record stays, marked `removed`, with the API calls of the removal.

```sh
python -m tgwitness.cloud destroy --record deployments/case-2026-11/deployment.json --confirm case-2026-11 \
    --provider-token-file hetzner.token --cloudflare-token-file cloudflare.token
```

Removal through the API is implemented for Hetzner. For other providers `destroy` stops before
deleting anything and names the label to delete in the provider's console. A hand-installed
server (`generic`) loses only its tunnel and DNS records. A quick tunnel deployment needs no
Cloudflare token: its tunnel ends with the server, and its posts expire from ntfy.sh within
12 hours.

## Any server (self-attested)

`--provider generic` is for a server bought or installed by hand. `deploy` creates the tunnel
and DNS, writes `install.sh` (private) and `install.redacted.sh` (to publish), and waits.
Copy `install.sh` to a freshly installed Ubuntu 24.04 server and run it there:

```sh
sudo bash install.sh
```

It records the host as it was (logins, accounts, `authorized_keys`, listening sockets,
services, scheduled jobs, packages), installs the commit, enables a host firewall, deletes
itself, masks SSH and ends the session. The report for such a server is at best
**SELF-ATTESTED**: whoever ran the installer had root before it, and no provider record is
available to the verifier. It is still better than an unexplained server: the inventory,
the installer hash and every later login are signed.

## Verify

The verifier needs `deployment.json`, the published installer, read-only credentials and,
ideally, a checkout of the commit and an evidence ZIP:

```sh
git clone -c core.autocrlf=false https://github.com/phishdestroy/TgWitness.git checkout
git -C checkout checkout 0123456789abcdef0123456789abcdef01234567
python -m tgwitness.cloud verify --record deployment.json \
    --provider-token-file read-only.token --cloudflare-token-file cloudflare-read.token \
    --fingerprint COLLECTOR_FINGERPRINT --cloud-init cloud-init.redacted.yaml \
    --source checkout --evidence tgwitness-evidence.zip --report report.md
```

Every provider and Cloudflare value is requested by the verifier at that moment; the record
supplies only the IDs to ask about. The exit code is 0 for **PASS**, 1 for **FAIL** and 2 for
**REVIEW**, **INCOMPLETE** or **SELF-ATTESTED**. `--fingerprint` should come from an independent
channel; without it the key is compared with the operator's record only. `python verify.py`
still verifies the evidence ZIP itself, as in [Evidence](EVIDENCE.md).

Provider actions are classified: creation and start within 30 minutes of creation pass;
console, rescue, password reset, rebuild, ISO, images, snapshots, backups, Systems Manager,
EC2 Instance Connect and firewall openings fail; power actions and anything not expected
are marked for review. An unknown action never passes silently.

## Report for evidence handover

`--report report.md` writes the Markdown report and `report.json` beside it:

1. result, collector key fingerprint, deployment, provider, commit, server, firewall, tunnel;
2. every check with its status and source (provider API, Cloudflare API, collector statement,
   evidence journal);
3. the provider log with each action's assessment and, where the provider records it, the actor;
4. the Cloudflare endpoints holding the tunnel's connections, configuration and audit log;
5. the signed collector statement;
6. what the report establishes and what it does not;
7. commands to reproduce it, and the SHA-256 of every file it was given.

Hand over the report, `report.json`, `deployment.json`, the published installer and the
evidence ZIP. Produce the report early: provider logs are kept for limited periods.

## Cloudflare as an outside witness

Everything here is optional. Without a Cloudflare account the server still runs, and two of
these work today:

| What | What it shows | In TgWitness |
| --- | --- | --- |
| Quick tunnel or your domain's tunnel | the panel is reached only through the tunnel | the server wizard, see above |
| drand relay `drand.cloudflare.com` | records after a drand round are newer than it: the journal was written as it went | evidence mode, **More witnesses**, no account ([format](EVIDENCE.md#optional-records-in-evidence-mode-drand-and-telegram-devices)) |
| Tunnel health notifications | when the tunnel was down, by email or webhook from Cloudflare | set them in the Cloudflare dashboard |
| Gateway DNS (`--gateway-dns`, or **Cloudflare Gateway DNS** in the wizard) | every name the server looked up, answered by Cloudflare over TLS; the Hetzner firewall lets DNS reach nothing else; whether a Gateway policy could rewrite answers | Hetzner, free Zero Trust plan, no domain; `verify` checks the firewall, the location, logging, policies, the server's queries and the audit log; evidence mode copies the log into the journal |
| Gateway with the Cloudflare One client on the server, an outbound firewall that allows only Cloudflare | every connection the server made, not just DNS | not built yet |
| Access in front of the panel | who signed in to the panel and when | not built: needs your own domain |
| SSH command logging | each command in a debug session | not built yet |

Logpush, which would keep Cloudflare's own copy in R2, is an Enterprise feature: on the free
plan Cloudflare answers `logpush is not enabled for this account`. Its Gateway log lasts 24
hours there, so evidence mode copies it into the signed journal (**Cloudflare Gateway's log of
this server's DNS queries**, a read-only token with Account Analytics Read).

Without a Zero Trust plan an account has one DNS location. When Cloudflare refuses another,
the server shares the existing one and its queries are told apart by its address; that filter
needs Zero Trust PII Read as well, and `destroy` leaves a shared location. One log query spans
at most three hours, so the copy and `verify` read the day in three-hour windows.

Gateway DNS covers the system resolver. DNS over HTTPS on port 443 to another resolver, and
connections to an address looked up nowhere (Telegram's data centres, for one), are not in
its log.

Cloudflare cannot see inside Telegram's encryption, other devices on the Telegram account
(evidence mode's device list records them from Telegram's side) or the provider's hypervisor.

On 1 November 2026 Gateway DNS ran against real Hetzner Cloud and a free Cloudflare account:
Hetzner accepted the outbound rules, the server installed v0.7.0 with every lookup going
through Gateway over TLS, the quick tunnel worked through that firewall, and `verify` read
the server's 19 names back from Cloudflare (Ubuntu and Hetzner mirrors, GitHub, PyPI, NTP,
the tunnel, ntfy.sh). The panel copied 36 queries in eight windows into a journal and
`verify.py` summarised them without gaps; `destroy` removed the server and firewall and left
the shared location.

## What this does not establish

- The provider and its staff control the hypervisor, disks and network.
- Host measurements are self-reported by the collector.
- Earlier firewall rule contents are not in every provider log; only Linode keeps rule versions.
- It says nothing new about message authenticity; see [Evidence](EVIDENCE.md).

## Tested here

The deployment, lock and verification logic is covered by automated tests against simulated
Hetzner, DigitalOcean, Linode, Vultr, EC2/CloudTrail and Cloudflare APIs built from their
published API references, and the AWS request signing against AWS's published examples.
`tools/check_cloud_wizard.py` runs the panel's server wizard the same way, with a domain and
with a quick tunnel. `tools/check_tdx.py` verifies real Intel TDX attestations from dcap-qvl and dstack
up to Intel's root certificate (sources in [tools/tdx/README.md](../tools/tdx/README.md)); `tools/check_phala.py`
runs deploy, verify, the journal, destroy and the panel wizard against a simulated Phala Cloud
whose attestations come from a forged PKI shaped like Intel's. The Phala path has not yet been
tried on Phala Cloud itself.

On 1 November 2026 the quick tunnel path ran against real **Hetzner Cloud** (Nuremberg, `cpx22`,
TgWitness v0.7.0), real ntfy.sh and GitHub, from the panel and from code:

- the price check, then creation from the panel's buttons: server running after 13 seconds,
  signed statement with matching instance and installer hashes after about two minutes;
- the server's own panel opened through its trycloudflare.com address and accepted the
  panel token; without the token it answers 401;
- after a reboot through the Hetzner API the server posted a new signed address, **Find the
  current address** found it, the old address stopped answering, the signing key stayed the
  same; an unsigned post to an ntfy.sh topic was ignored;
- `verify` against Hetzner's API: server, firewall without inbound rules, statement, binding,
  host measurements, boot and the source hash of a v0.7.0 checkout passed; the Cloudflare
  checks were unavailable, as described above; the installer differed from the one v0.7.0
  builds and equalled byte for byte the one this version's code builds;
- deletion from the panel removed exactly the server and firewall the deployment labelled;
  other servers and firewalls in the same project were untouched.

Not yet run against real accounts: a deployment under your own domain (Cloudflare tunnel and
DNS), the other providers, a debug deployment and `lock`, a Telegram account on such a server,
and the live updates of later versions through a quick tunnel. Check the first deployment on
each provider with `plan`, a debug deployment and `verify` before relying on it in a case.
