[TgWitness](../../README.md) / [tgwitness_capture](../README.md)

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-capture-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-capture-static.svg">
  <source media="(max-width: 640px)" srcset="../../docs/assets/presentation/section-capture-mobile.svg">
  <img src="../../docs/assets/presentation/section-capture.svg" width="1200" alt="TgWitness / Independent capture">
</picture>

# Recorder interfaces

Browser interfaces served by the independent capture package.

| Interface | Files |
| --- | --- |
| Generic browser and AyuGram recorder | [`index.html`](index.html), [`app.js`](app.js), [`style.css`](style.css) |
| Official Web witness | [`official.html`](official.html), [`official.js`](official.js), [`official-locales.js`](official-locales.js), [`official.css`](official.css) |
| Trusted Live | [`trusted.html`](trusted.html), [`trusted.js`](trusted.js), [`trusted.css`](trusted.css) |
| Official-client page handling | [`official-guard.js`](official-guard.js), [`official-rendered-text.js`](official-rendered-text.js) |

Run the interfaces through their recorder service so authentication and controls
use the correct API. The [add-on guide](../../addons/capture/README.md) describes
startup and login; private capture regressions cover the synthetic browser flows.
