import json
import re
from collections import Counter
from html import unescape

import pytest
from fastapi.testclient import TestClient

from tgwitness import alerts, i18n
from tgwitness.app import create_app
from tools.i18n_keys import STATIC, all_script_keys, server_keys

TRANSLATED = [lang for lang in i18n.LANGUAGES if lang != "en"]
CATEGORIES = {"zero", "one", "two", "few", "many", "other"}
holes = lambda text: sorted(re.findall(r"\{(\w+)\}", text))
tags = lambda text: sorted(re.findall(r"<(/?[a-z]+)", text))


def forms(value):
    return list(value.values()) if isinstance(value, dict) else [value]


def test_every_language_has_one_locale_file_with_the_same_keys():
    assert sorted(path.stem for path in i18n.LOCALES.glob("*.json")) == sorted(TRANSLATED)
    english = set(i18n.words(TRANSLATED[0]))
    for lang in TRANSLATED:
        assert set(i18n.words(lang)) == english, lang


def test_panel_scripts_and_server_messages_have_dictionary_coverage():
    needed = set(all_script_keys()) | set(server_keys())
    assert len(needed) > 500
    for lang in TRANSLATED:
        missing = needed - set(i18n.words(lang))
        assert not missing, (lang, sorted(missing)[:5])


def test_full_site_and_panel_languages_cannot_drift_apart():
    from tools.site_i18n import LANGUAGES as site_languages
    assert tuple(site_languages) == i18n.LANGUAGES
    assert 'de' in i18n.LANGUAGES and 'he' in i18n.LANGUAGES and 'zh-Hant' in i18n.LANGUAGES


def test_existing_fallback_keys_have_real_catalogue_entries_in_every_panel_language():
    fallback = set(json.loads(i18n.ENGLISH_FALLBACKS.read_text(encoding='utf-8')))
    for lang in TRANSLATED:
        values = json.loads((i18n.LOCALES / (lang + '.json')).read_text(encoding='utf-8'))
        assert not fallback - values.keys(), lang


def test_fallback_catalog_is_explicit_english_and_preserves_translations():
    fallback = json.loads(i18n.ENGLISH_FALLBACKS.read_text(encoding="utf-8"))
    assert fallback and len(fallback) == len(set(fallback))
    for lang in TRANSLATED:
        translated = json.loads((i18n.LOCALES / (lang + ".json")).read_text(encoding="utf-8"))
        dictionary = i18n.words(lang)
        assert all(dictionary[key] == translated.get(key, key) for key in fallback)
        assert all(dictionary[key] == value for key, value in translated.items())


@pytest.mark.parametrize("lang", TRANSLATED)
def test_translations_keep_placeholders_and_markup(lang):
    for key, value in i18n.words(lang).items():
        if isinstance(value, dict):
            assert "other" in value and set(value) <= CATEGORIES, (lang, key)
        for text in forms(value):
            assert text.strip(), (lang, key)
            assert holes(text) == holes(key), (lang, key, text)
            assert tags(text) == tags(key), (lang, key, text)


def test_language_picker_lists_exactly_the_supported_languages():
    script = (STATIC / "i18n.js").read_text(encoding="utf-8")
    listed = re.search(r"const PANEL_LANGUAGES=\{(.*?)\};", script, re.S).group(1)
    codes = [a or b for a, b in re.findall(r'(?:"([\w-]+)"|(\w+)):"', listed)]
    assert codes == list(i18n.LANGUAGES)
    extra = re.search(r"const GUIDE_LANGUAGES=\{\.\.\.PANEL_LANGUAGES,(.*?)\};", script, re.S).group(1)
    codes = [a or b for a, b in re.findall(r'(?:"([\w-]+)"|(\w+)):"', extra)]
    assert (*i18n.LANGUAGES, *codes) == i18n.GUIDE_LANGUAGES


def test_guide_catalogs_cover_both_pages_and_preserve_commands_and_links():
    inventory = json.loads((i18n.GUIDE_LOCALES / "keys.json").read_text(encoding="utf-8"))
    required = set(inventory["keys"])
    assert required and len(required) == len(inventory["keys"])
    assert all(set(keys) <= required for keys in inventory["pages"].values())
    for lang in i18n.GUIDE_LANGUAGES[1:]:
        dictionary = i18n.guide_words(lang)
        assert required <= dictionary.keys(), lang
        if lang not in i18n.LANGUAGES:
            assert dictionary.keys() == required, lang
        for key in required:
            value = dictionary[key]
            assert value.strip() and holes(value) == holes(key) and tags(value) == tags(key), (lang, key)
            protected = lambda text: Counter(unescape(x) for x in re.findall(r'<(?:code|kbd)[^>]*>(.*?)</(?:code|kbd)>', text))
            assert protected(value) == protected(key), (lang, key)
            links = lambda text: Counter(re.findall(r'(?:href|src)="([^"]*)"', text))
            assert links(value) == links(key), (lang, key)


@pytest.mark.parametrize("tag,expected", [("de-DE", "de"), ("he-IL", "he"), ("zh-Hant", "zh-Hant"),
                                        ("zh-TW", "zh-Hant"), ("zh-Hant-HK", "zh-Hant"), ("zh-CN", "zh")])
def test_guide_browser_language_and_chinese_script_selection(tag, expected):
    assert i18n.pick(None, tag + ",en;q=0.5", i18n.GUIDE_LANGUAGES) == expected


def test_language_choice_order():
    assert i18n.pick("ru", "es-ES,es;q=0.9") == "ru"
    assert i18n.pick("xx", "pt-BR,pt;q=0.9,en;q=0.5") == "pt"
    assert i18n.pick(None, "de-DE,zh-CN;q=0.8,ru;q=0.5") == "de"
    assert i18n.pick(None, "uk;q=0.2,es;q=0.7") == "es"
    assert i18n.pick(None, "am,fr;q=0") == "en"
    assert i18n.pick(None, None) == "en"


def test_locale_script_follows_cookie_and_browser_language(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    with TestClient(create_app(tmp_path, demo=True)) as c:
        response = c.get("/locale.js", headers={"Accept-Language": "ar,en;q=0.5"})
        assert response.headers["content-type"].startswith("text/javascript")
        assert response.text.startswith('window.TGW_LANG="ar";window.TGW_DICT={')
        c.cookies.set(i18n.COOKIE, "uk")
        body = c.get("/locale.js", headers={"Accept-Language": "ar"}).text
        assert body.startswith('window.TGW_LANG="uk";')
        dictionary = json.loads(body.split("window.TGW_DICT=", 1)[1].rstrip().rstrip(";"))
        assert dictionary == i18n.words("uk")
        c.cookies.set(i18n.COOKIE, "en")
        assert c.get("/locale.js").text == 'window.TGW_LANG="en";window.TGW_DICT={};\n'


def test_notification_texts_use_the_chosen_language():
    words = i18n.words("es")
    text = alerts.tr(words, "Disk almost full: {size} free. Photo and file downloads are paused.", size="12.0 MB")
    assert "12.0 MB" in text and text != "Disk almost full: 12.0 MB free. Photo and file downloads are paused."
    assert alerts.tr({}, "{chat}: {deleted} deleted", chat="A", deleted=2) == "A: 2 deleted"
    assert alerts.tr({}, "Keep {unknown}") == "Keep {unknown}"


def test_guide_locale_endpoint_has_all_translations_and_keeps_panel_scope(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    with TestClient(create_app(tmp_path, demo=True)) as client:
        client.cookies.set(i18n.COOKIE, "ru")
        for lang in i18n.GUIDE_LANGUAGES:
            response = client.get("/locale.js", params={"scope": "guide", "lang": lang})
            assert response.status_code == 200
            assert response.content == i18n.script(lang, guide=True)

        assert client.get("/locale.js?scope=guide&lang=../private").content == i18n.script("ru", guide=True)
        assert client.get("/locale.js?lang=de").content == i18n.script("de")
        client.cookies.clear()
        assert client.get("/locale.js?scope=guide", headers={"Accept-Language": "zh-TW"}).content == i18n.script("zh-Hant", guide=True)
