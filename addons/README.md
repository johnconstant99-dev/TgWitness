[TgWitness](../README.md)

<picture>
  <source media="(max-width: 640px)" srcset="../docs/assets/presentation/section-capture-mobile.svg">
  <img src="../docs/assets/presentation/section-capture.svg" width="1200" alt="TgWitness / Independent capture">
</picture>

# Optional add-ons

Separate components for capture workflows beyond the main Telegram collector.

| Component | Start here |
| --- | --- |
| Independent browser and AyuGram recorders | [Capture installation and controls](capture/README.md) |
| Official Telegram Web witness | [Official-client procedure](../docs/OFFICIAL-WITNESS.md) |
| Trusted Live | [Desktop and Web session procedure](../docs/TRUSTED-LIVE.md) |

The package source is in [`tgwitness_capture/`](../tgwitness_capture/README.md).
Its [configuration examples](capture/config/README.md),
[container definitions](capture/deploy/README.md) and
[tests](capture/tests/README.md) live beside the add-on packaging.

Start with the procedure for the mode you need: its client, recording policy and
verification inputs determine the setup.
