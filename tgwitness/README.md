[TgWitness](../README.md)

<picture>
  <source media="(max-width: 640px)" srcset="../docs/assets/presentation/section-source-mobile.svg">
  <img src="../docs/assets/presentation/section-source.svg" width="1200" alt="TgWitness / Application">
</picture>

# Application source

TgWitness's Python package: the authenticated panel, account collectors, observation
journal, exports and optional witness services. Start with the component map below;
the detailed data model lives in [Architecture](../docs/ARCHITECTURE.md).

## Find the component

| Area | Files | Responsibility |
| --- | --- | --- |
| Application and accounts | [`app.py`](app.py), [`profiles.py`](profiles.py), [`__main__.py`](__main__.py) | Panel/API, isolated account workspaces and command-line entry points |
| Observation | [`collector.py`](collector.py), [`scope.py`](scope.py), [`monitoring.py`](monitoring.py) | Account-visible updates, selected sources and capture policy |
| Journal and evidence | [`store.py`](store.py), [`evidence.py`](evidence.py), [`verify.py`](verify.py) | Stored records, signed handoffs and standalone verification |
| Search | [`fulltext.py`](fulltext.py), [`search_api.py`](search_api.py) | Derived full-text index bound to the journal head and ranked search API |
| Scripts and agents | [`cli.py`](cli.py), [`archive.py`](archive.py), [`archive_api.py`](archive_api.py), [`activity.py`](activity.py), [`mcp_server.py`](mcp_server.py) | Command line, scoped archive API and connections, activity statistics, MCP transports |
| Investigation views | [`dossier.py`](dossier.py), [`chat_export.py`](chat_export.py), [`message_content.py`](message_content.py) | Saved people observations, chat-history exports and comparable content |
| Deliberate actions | [`interactions.py`](interactions.py), [`keyboard.py`](keyboard.py), [`telegram_client.py`](telegram_client.py) | Panel actions, saved buttons and transport handling |
| Connections | [`network.py`](network.py), [`netclient.py`](netclient.py), [`proxy_catalog.py`](proxy_catalog.py) | Per-account routes and public proxy catalogs |
| Secrets and imports | [`security.py`](security.py), [`account_import.py`](account_import.py), [`sessions.py`](sessions.py), [`tdata.py`](tdata.py) | Vault access and bounded account import handling |
| Independent checks | [`witness.py`](witness.py), [`witness_api.py`](witness_api.py), [`anchor.py`](anchor.py), [`anchoring.py`](anchoring.py) | Witness checkpoints and external timestamps |
| Operations | [`alerts.py`](alerts.py), [`replica.py`](replica.py), [`doctor.py`](doctor.py), [`tuning.py`](tuning.py) | Notifications, off-site copies, local diagnostics and operating parameters |
| Interface | [`static/`](static/README.md), [`locales/`](locales/README.md), [`i18n.py`](i18n.py) | Bundled UI and interface translations |
| Report metrics | [`metrics/`](metrics/README.md) | Versioned statistics derived from saved events |
| Cloud adapters | [`providers/`](providers/README.md) | Provider-specific deployment and access handling |
| Case Board contracts | [`schemas/`](schemas/README.md) | Generated JSON Schemas for board operations |
| Report resources | [`fonts/`](fonts/README.md) | Bundled fonts and licences |

Setup-page translations have a separate [guide catalog](guide_locales/README.md).

## Work on the package

Follow the [development setup](../.github/CONTRIBUTING.md#development-setup), then use the
[browser checks](../tools/README.md) for the affected
workflow. Keep normalization in presentation/search separate from signed payloads.

Read the [evidence format](../docs/EVIDENCE.md) before changing a journal or export.
