import pytest

from tools.build_source import FILES, public_sources


def test_public_archive_excludes_runtime_artifacts_even_inside_source_trees(tmp_path):
    for name in FILES:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("Synthetic source file", encoding="utf-8")
    public = ["tgwitness/app.py", "tgwitness/static/app.js", "docs/assets/workspace.png",
              ".github/ISSUE_TEMPLATE/bug_report.yml", "deploy/tgwitness.service",
              "tgwitness/locales/ru.json", "tgwitness/english_fallbacks.json", "tgwitness/public_proxies.json",
              "tgwitness/guide_locales/keys.json", "tgwitness/guide_locales/de.json", "tgwitness/guide_locales/zh-Hant.json",
              "website/i18n/ru.json",
              "docs/assets/presentation/investigation-overview.mp4",
              "docs/assets/presentation/investigation.mp4", "docs/assets/presentation/investigation.gif",
              "docs/assets/presentation/message-history.mp4", "docs/assets/presentation/message-history.gif"]
    private = ["tgwitness/.env", "tgwitness/session.tgwitness-session", "docs/panel-token.txt",
               "tools/account.session", "tools/credentials.enc", "tests/secret.key",
               "docs/journal.sqlite3", "tgwitness/__pycache__/app.pyc", "data/app.py",
               "tgwitness/account.json", "tgwitness/vault.external.json",
               "tgwitness/locales/account.json", "tgwitness/static/credentials.json",
               "tgwitness/guide_locales/account.json",
               "website/accounts.json", "website/i18n/account.json",
               "docs/assets/account-recording.mp4", "docs/assets/presentation/private-capture.gif",
               "docs/assets/presentation/investigation-copy.mp4", "website/investigation.mp4",
               "tgwitness/data/account.json", "tgwitness/data/notes.py",
               "docs/tgwitness-backup-old/report.md", "tools/.venv/helper.py",
               "tgwitness/proof-data/private.py", "docs/proof-config/secret.md", "tools/witness-data/private.py", "docs/proxy-config/private.md"]
    for name in [*public, *private]:
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"synthetic")
    selected = {p.relative_to(tmp_path).as_posix() for p in public_sources(tmp_path)}
    assert selected == set(FILES) | set(public)


def test_public_archive_refuses_symlinked_source(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    for name in FILES:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text("Synthetic source file", encoding="utf-8")
    outside = tmp_path / "private.txt"
    outside.write_text("Synthetic secret", encoding="utf-8")
    link = root / "tools/linked.py"
    link.parent.mkdir(exist_ok=True)
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation is unavailable on this filesystem")
    with pytest.raises(ValueError, match="ordinary repository file"):
        public_sources(root)
