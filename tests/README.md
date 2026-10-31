![Tests](../docs/assets/presentation/folder-tests.svg)

# Tests

Fake Telegram clients and temporary workspaces. No Telegram login needed.
Live-run results are in [VERIFICATION.md](../docs/VERIFICATION.md).

## Run

After [dev setup](../.github/CONTRIBUTING.md#development-setup):

```sh
python -m pytest -q
```

For an export fix, start small:

```sh
python -m pytest -q tests/test_evidence.py tests/test_chat_export.py
```

| Area | Start here |
| --- | --- |
| Evidence / exports | [evidence](test_evidence.py), [chat export](test_chat_export.py), [multi-account](test_multi_export.py), [lifecycle](test_export_lifecycle.py), [ZIP limits](test_verify_limits.py) |
| Capture | [collector](test_collector.py), [scope](test_scope.py), [coverage](test_coverage.py), [recheck](test_recheck.py) |
| Accounts / network | [isolation](test_account_isolation.py), [import](test_account_import.py), [connection](test_connection.py), [HTTP](test_netclient.py) |
| Investigation | [search](test_investigation.py), [dossiers](test_dossier.py), [interactions](test_interactions.py) |
| Witness / backup | [witness](test_witness.py), [timestamps](test_anchor.py), [S3](test_replica.py) |
| UI / docs | [i18n](test_i18n.py), [site](test_site.py), [Wiki](test_wiki.py), [markup](test_docs_markup.py) |
| Packaging | [installers](test_installers.py), [release](test_release.py), [publication](test_publication.py), [portable ZIP](test_portable.py) |

Browser checks live in [tools/](../tools/README.md).
