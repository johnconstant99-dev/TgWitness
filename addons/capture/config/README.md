[TgWitness](../../../README.md) / [capture](../README.md)

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../../../docs/assets/presentation/section-capture-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../../../docs/assets/presentation/section-capture-static.svg">
  <source media="(max-width: 640px)" srcset="../../../docs/assets/presentation/section-capture-mobile.svg">
  <img src="../../../docs/assets/presentation/section-capture.svg" width="1200" alt="TgWitness / Independent capture">
</picture>

# Recorder configuration

Example settings for the independent capture package. Copy the relevant file
into your private configuration directory and adjust it before starting a recorder.

| Example | Mode |
| --- | --- |
| [`browser.example.json`](browser.example.json) | Attach to a separately running Chromium CDP endpoint |
| [`ayugram.example.json`](ayugram.example.json) | Snapshot an existing AyuGram database |
| [`official.example.json`](official.example.json) | Official Telegram Web witness |
| [`official-upstream.example.json`](official-upstream.example.json) | Upstream connection settings for the official-client procedure |
| [`trusted.example.json`](trusted.example.json) | Trusted Live session |

For the generic recorders, pass your copy with `--config` when running
`python -m tgwitness_capture serve`. Paths, client versions and route labels must
describe your installation.

[Generic recorder setup](../README.md#local-installation) ·
[Official-client procedure](../../../docs/OFFICIAL-WITNESS.md) ·
[Trusted Live](../../../docs/TRUSTED-LIVE.md)
