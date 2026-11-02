import json
from pathlib import Path
import re

try:
    from .i18n_keys import LITERAL, js_literal, script_keys
except ImportError:
    from i18n_keys import LITERAL, js_literal, script_keys

ROOT = Path(__file__).resolve().parents[1]


def board_keys(source=None):
    if source is None:
        source = (ROOT / "tgwitness/static/views/board.js").read_text(encoding="utf-8")
    keys = script_keys(source)
    literal = LITERAL.pattern
    for pattern in (
        r"(?<![\w.$])(?:t|btn|modal)\(\s*" + literal,
        r"(?<![\w.$])(?:field|select)\(\s*\w+\s*,\s*" + literal,
    ):
        keys.extend(js_literal(match.group(2)) for match in re.finditer(pattern, source))
    # Static [value, label] option tables also feed select(), field() and btn().
    token = r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')'''
    for match in re.finditer(r"\[\s*(" + token + r")\s*,\s*(" + token + r")\s*\]", source):
        value, label = (js_literal(value[1:-1]) for value in match.groups())
        if not re.search(r"[A-Z]", value):
            keys.append(label)
    for match in re.finditer(r"\bt\(\{(.*?)\}\[", source, re.S):
        keys.extend(js_literal(value.group(2)) for value in re.finditer(r":\s*" + literal, match.group(1)))
    for match in re.finditer(r"\bmodal\(\w+\s*\?\s*(" + token + r")\s*:\s*(" + token + r")\s*\)", source):
        keys.extend(js_literal(value[1:-1]) for value in match.groups())
    for match in re.finditer(r"for\(const\s+title\s+of\s+\[([^\]]+)\]\)", source):
        keys.extend(js_literal(value.group(2)) for value in LITERAL.finditer(match.group(1)))
    return list(dict.fromkeys(key for key in keys if re.search(r"[A-Za-z]{2}", key)))


def validate_catalogue(keys, words, lang):
    missing = [key for key in keys if key not in words]
    assert not missing, (lang, "Missing raw Case Board translations", missing)
    for key in keys:
        value = words[key]
        variants = value if isinstance(value, dict) else {"string": value}
        assert variants and (not isinstance(value, dict) or "other" in value), (lang, key, "Missing plural fallback")
        for form, text in variants.items():
            assert isinstance(text, str) and text.strip(), (lang, key, form, "Empty translation")
            assert sorted(re.findall(r"\{\w+\}", key)) == sorted(re.findall(r"\{\w+\}", text)), (lang, key, form, "Changed placeholders")


def check_translations():
    from tgwitness import i18n

    # Exercise helper labels and ensure implementation values are not mistaken for UI text.
    fixture = """
        t('Direct label'); tr('{n} cards', {n: count}); btn('Button label', action);
        field(form, 'Field label', 'textarea'); select(form, 'Select label', [['id', 'Option label']]);
        modal(item ? 'Edit label' : 'New label'); t({'board.bookmark':'Kind label'}[kind]);
        for(const title of ['Column label']) head.append(t(title));
        ['AbortError', 'StaleView'].includes(error.name);
    """
    assert set(board_keys(fixture)) == {
        "Direct label", "{n} cards", "Button label", "Field label", "Select label",
        "Option label", "Edit label", "New label", "Kind label", "Column label",
    }
    keys = board_keys()
    for lang in i18n.LANGUAGES:
        if lang == "en":
            continue
        words = json.loads((i18n.LOCALES / (lang + ".json")).read_text(encoding="utf-8"))
        validate_catalogue(keys, words, lang)
    try:
        validate_catalogue(["Case Board"], {}, "synthetic")
    except AssertionError:
        pass
    else:
        raise AssertionError("Missing raw translations must fail even when runtime English fallback exists")
    return f"Case Board: {len(keys)} source keys complete in all {len(i18n.LANGUAGES) - 1} raw translated catalogues"
