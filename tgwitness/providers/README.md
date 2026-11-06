[TgWitness](../../README.md) / [tgwitness](../README.md)

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-source-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-source-static.svg">
  <source media="(max-width: 640px)" srcset="../../docs/assets/presentation/section-source-mobile.svg">
  <img src="../../docs/assets/presentation/section-source.svg" width="1200" alt="TgWitness / Application">
</picture>

# Cloud provider adapters

Provider implementations used by the cloud deployment flow. The common API and
provider contract live in [`base.py`](base.py); [`__init__.py`](__init__.py) selects
an adapter by name.

| Adapter | Provider |
| --- | --- |
| [`hetzner.py`](hetzner.py) | Hetzner |
| [`digitalocean.py`](digitalocean.py) | DigitalOcean |
| [`linode.py`](linode.py) | Linode |
| [`vultr.py`](vultr.py) | Vultr |
| [`aws.py`](aws.py) | AWS |
| [`phala.py`](phala.py) | Phala |
| [`generic.py`](generic.py) | Generic deployment |

For the operator workflow and verification inputs, read
[High-assurance deployment](../../docs/HIGH-ASSURANCE.md).
Adapter definitions include credentials, defaults, access descriptions and
provider-specific limits; inspect those before changing a deployment path.

The [cloud wizard checks](../../tools/check_cloud_wizard.py) and
[Phala checks](../../tools/check_phala.py) use simulated services for their
configured scenarios. Running a provider deployment is a separate operation.
