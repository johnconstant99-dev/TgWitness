[TgWitness](../../README.md) / [tgwitness](../README.md)

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-source-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-source-static.svg">
  <source media="(max-width: 640px)" srcset="../../docs/assets/presentation/section-source-mobile.svg">
  <img src="../../docs/assets/presentation/section-source.svg" width="1200" alt="TgWitness / Application">
</picture>

# Workspace interface

The bundled browser interface served by TgWitness. These are application files;
the separate public documentation website lives in [`website/`](../../website/README.md).

## Files at a glance

| File | Purpose |
| --- | --- |
| [`index.html`](index.html), [`app.js`](app.js), [`style.css`](style.css) | Main workspace, account views, interactions and responsive layout |
| [`theme.js`](theme.js) | Light/dark theme handling |
| [`i18n.js`](i18n.js) | Interface translation handling |
| [`guide.html`](guide.html), [`guide.js`](guide.js), [`guide.css`](guide.css) | In-application setup guidance |
| [`dedicated-account.html`](dedicated-account.html) | Dedicated-account guide |
| [`mark.svg`](mark.svg) | Original TgWitness application mark |
| [`core/`](core/README.md) | View lifecycle, time display and workspace identity |
| [`components/`](components/README.md) | Shared controls, forms, status and notifications |
| [`views/`](views/README.md) | Screen-specific modules and styles |

## Review a change

Use the [demo](../../docs/QUICKSTART.md#explore-the-interface) for fictional content.
Check both themes, keyboard navigation and a narrow viewport. Use the relevant
[browser acceptance tool](../../tools/README.md) and refresh screenshots only from
synthetic data. Interface strings belong in the [locale workflow](../locales/README.md).
