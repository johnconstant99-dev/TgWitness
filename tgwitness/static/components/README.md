[TgWitness](../../../README.md) / [static](../README.md)

<picture>
  <source media="(max-width: 640px)" srcset="../../../docs/assets/presentation/section-source-mobile.svg">
  <img src="../../../docs/assets/presentation/section-source.svg" width="1200" alt="TgWitness / Application">
</picture>

# Shared interface components

Browser components used across the workspace: forms, collection controls, health
status, notifications and common feedback.

| Start with | For changes to |
| --- | --- |
| [`forms.js`](forms.js), [`forms.css`](forms.css) | Shared form behavior and presentation |
| [`collection.js`](collection.js), [`collection.css`](collection.css) | Collection controls |
| [`health.js`](health.js), [`health-actions.js`](health-actions.js), [`health.css`](health.css) | Health status and available actions |
| [`notifications.js`](notifications.js), [`notifications.css`](notifications.css) | Notification UI |
| [`account-state.js`](account-state.js), [`connection-notice.js`](connection-notice.js) | Account and connection state |
| [`feedback.css`](feedback.css), [`shell.css`](shell.css) | Shared feedback and shell styling |

Review a shared component on the screens that use it, in both themes and at a
narrow width. Follow the [interface guide](../README.md) and keep visible strings
in the [translation workflow](../../locales/README.md).
