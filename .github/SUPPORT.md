# Get help with TgWitness

Start with the [wiki](../docs/wiki/Home.md), [troubleshooting](../docs/wiki/Troubleshooting.md) or [FAQ](../docs/wiki/FAQ.md). The [technical documentation](../docs/README.md) covers formats, deployment and operation in more detail.

## Choose the right report

| Need | Where to go |
| --- | --- |
| Installation or usage help | Read the relevant wiki page, then open an issue if the question remains |
| Reproducible malfunction | Use the **Bug report** issue template |
| Missing or incorrect instructions | Use the **Documentation issue** template |
| A workflow the tool should support | Use the **Feature request** template |
| A suspected vulnerability | Follow [SECURITY.md](SECURITY.md) |

Use the project's **Issues** tab. Search existing issues first.

## Include enough to reproduce

- TgWitness version and installation method: source, portable or Docker.
- Operating system, Python version where applicable, and browser.
- The page or command involved and the steps that led to the problem.
- Expected result, actual result and a redacted error message.
- Whether the case uses demo data, a synthetic transport or live Telegram.

Prefer a small synthetic example. A screenshot with fictional conversations is more useful than a real account dump. For connection problems, state the route type without its credentials.

## Keep private material private

Do not attach session files, a data directory, API credentials, panel or bot tokens, private keys, real message content or evidence archives. If a secret has already been published, remove it from the public report and revoke or replace the affected authorization through the relevant service.

Security reports use the private process in [SECURITY.md](SECURITY.md). If private reporting is unavailable, ask for a private channel without posting exploit details.

## Scope of support

TgWitness is a self-hosted project. There is no hosted collector, managed account service or guaranteed response time. The [verification record](../docs/VERIFICATION.md) distinguishes completed checks from remaining qualification work.

For code or documentation changes, see [CONTRIBUTING.md](CONTRIBUTING.md).
