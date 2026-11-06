[TgWitness](../../../README.md) / [static](../README.md)

<picture>
  <source media="(max-width: 640px)" srcset="../../../docs/assets/presentation/section-source-mobile.svg">
  <img src="../../../docs/assets/presentation/section-source.svg" width="1200" alt="TgWitness / Application">
</picture>

# Interface foundations

Shared browser code for view lifecycle, time display and workspace identity.

| Module | Responsibility |
| --- | --- |
| [`view-host.js`](view-host.js) | Coordinate view state and lifecycle |
| [`time.js`](time.js) | Shared time presentation |
| [`workspace-safety.js`](workspace-safety.js) | Keep the URL, selected account and server response in the same workspace |

Changes here can affect several screens. Follow the
[interface review procedure](../README.md#review-a-change), including account
switching and navigation while requests are still pending.

[Shared components](../components/README.md) · [Screen modules](../views/README.md)
