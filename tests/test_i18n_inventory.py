import json

from tools import i18n_keys
from tools.i18n_keys import DYNAMIC_SCRIPT_KEYS, PACKAGE, script_keys


def test_panel_inventory_handles_both_js_quote_styles_and_member_calls():
    source = r'''ctx.tr('Save changes'); tr("Already saved"); tr('Don\'t lose the draft');'''
    assert script_keys(source) == ["Save changes", "Already saved", "Don't lose the draft"]


def test_js_escapes_preserve_the_runtime_key_and_plural_forms():
    source = r'''tr('A \\"quoted\\" path'); tr('Line\nnext'); tr('Caf\u00e9'); tr('Hello \u{1F44B}');
                trn('{n} account', '{n} accounts', n);'''
    assert script_keys(source) == ['A \\"quoted\\" path', "Line\nnext", "Café", "Hello 👋", "{n} account", "{n} accounts"]


def test_conditional_keys_exclude_compared_values():
    assert script_keys("tr(state === 'failed' ? 'Try again' : 'Continue')") == ["Try again", "Continue"]


def test_inventory_includes_table_driven_journal_sources_and_health_controls():
    assert {"Previous record", "Apply dates", "Round video messages", "Ignore until visible", "Clear waiting queue"} <= set(DYNAMIC_SCRIPT_KEYS)


def test_inventory_discovers_native_modules_and_new_top_level_scripts(tmp_path, monkeypatch):
    for existing in i18n_keys.STATIC.glob("*.js"):
        (tmp_path / existing.name).write_text("", encoding="utf-8")
    for relative, key in (
        ("new-panel-feature.js", "Future top-level feature"),
        ("components/notice.js", "Component action"),
        ("views/journal.js", "Journal filter"),
        ("core/clock.js", "Clock description"),
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"tr({json.dumps(key)})", encoding="utf-8")
    monkeypatch.setattr(i18n_keys, "STATIC", tmp_path)
    assert {"Future top-level feature", "Component action", "Journal filter", "Clock description"} <= set(i18n_keys.all_script_keys())


def test_file_extensions_remain_literal_in_every_panel_catalogue():
    for path in (PACKAGE / "locales").glob("*.json"):
        dictionary = json.loads(path.read_text(encoding="utf-8"))
        for extension in (".zip", ".session", ".txt", ".json"):
            key = f"<code>{extension}</code>"
            assert dictionary[key] == key, (path.stem, key)
