[TgWitness](../../../README.md) / [capture](../README.md)

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../../../docs/assets/presentation/section-capture-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../../../docs/assets/presentation/section-capture-static.svg">
  <source media="(max-width: 640px)" srcset="../../../docs/assets/presentation/section-capture-mobile.svg">
  <img src="../../../docs/assets/presentation/section-capture.svg" width="1200" alt="TgWitness / Independent capture">
</picture>

# Capture containers

Container builds and client policies for the optional recording modes.
Select a Compose configuration in the [parent directory](../README.md) before
working with an individual Dockerfile.

| Files | Role |
| --- | --- |
| [Dockerfile](Dockerfile) | Independent recorder service |
| [Dockerfile.neko](Dockerfile.neko), [`neko-start.sh`](neko-start.sh) | Browser desktop used by the generic capture profile |
| [Dockerfile.gateway](Dockerfile.gateway), [upstream-proxy.example.conf](upstream-proxy.example.conf) | Browser forwarding gateway |
| [Dockerfile.official](Dockerfile.official), [`official-start.sh`](official-start.sh) | Official Web witness runtime |
| [`official-seccomp.json`](official-seccomp.json) | Browser syscall policy; read the [policy notes](official-seccomp.README.md) |
| [Dockerfile.trusted](Dockerfile.trusted), [`trusted-entrypoint.py`](trusted-entrypoint.py), [`trusted-display.py`](trusted-display.py) | Trusted Live runtime and display |
| [`chromium-policy.json`](chromium-policy.json), [chromium.conf](chromium.conf) | Managed browser configuration |

Mode-specific setup lives in [Optional capture](../../../docs/OPTIONAL-CAPTURE.md),
[Official Web witness](../../../docs/OFFICIAL-WITNESS.md) and
[Trusted Live](../../../docs/TRUSTED-LIVE.md). The
[capture tests](../tests/README.md) describe the available local checks.
