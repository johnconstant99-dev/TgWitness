import json
from functools import lru_cache
from pathlib import Path

from .failures import TEXTS

LANGUAGES = ("en", "ru", "uk", "es", "pt", "tr", "ar", "fa", "ur", "hi", "id", "vi", "zh",
             "fr", "de", "it", "uz", "ko", "zh-Hant", "ms", "pl", "ja", "th", "he", "bn")
GUIDE_LANGUAGES = (*LANGUAGES, "am")
COOKIE = "tgwitness-lang"
LOCALES = Path(__file__).parent / "locales"
GUIDE_LOCALES = Path(__file__).parent / "guide_locales"
ENGLISH_FALLBACKS = Path(__file__).parent / "english_fallbacks.json"
LOCALE_FILES = {code: LOCALES / (code + ".json") for code in LANGUAGES if code != "en"}
GUIDE_FILES = {code: GUIDE_LOCALES / (code + ".json") for code in GUIDE_LANGUAGES if code not in LANGUAGES}


def language_tag(tag, languages=LANGUAGES):
    tag = (tag or "").strip().lower().replace("_", "-")
    known = {code.lower(): code for code in languages}
    if tag in known:
        return known[tag]
    if tag.startswith('zh-') and any(part in ('hant', 'tw', 'hk', 'mo') for part in tag.split('-')[1:]):
        return known.get('zh-hant')
    return known.get(tag.split('-')[0])


def pick(cookie, accept, languages=LANGUAGES):
    if cookie in languages:
        return cookie
    choices = []
    for order, part in enumerate((accept or "").split(",")):
        tag, *params = part.strip().split(";")
        weight = 1.0
        for param in params:
            name, _, value = param.strip().partition("=")
            if name == "q":
                try:
                    weight = float(value)
                except ValueError:
                    weight = 0.0
        if weight > 0:
            choices.append((-weight, order, language_tag(tag, languages)))
    return next((lang for _, _, lang in sorted(choices) if lang in languages), "en")


def words(lang):
    if lang == "en":
        return {}
    path = LOCALE_FILES.get(lang)
    if path is None:
        raise ValueError("Unsupported panel language")
    fallback = {text: text for text in json.loads(ENGLISH_FALLBACKS.read_text(encoding="utf-8"))}
    return {**fallback, **json.loads(path.read_text(encoding="utf-8"))}


@lru_cache(maxsize=None)
def script(lang, guide=False):
    dictionary = guide_words(lang) if guide else words(lang)
    scope = 'window.TGW_SCOPE="guide";' if guide else 'window.TGW_ERRORS=' + json.dumps(TEXTS, separators=(",", ":")) + ';'
    return (scope + "window.TGW_LANG=" + json.dumps(lang) + ";window.TGW_DICT="
            + json.dumps(dictionary, ensure_ascii=False, separators=(",", ":")) + ";\n").encode("utf-8")


def guide_words(lang):
    if lang in LANGUAGES:
        return words(lang)
    path = GUIDE_FILES.get(lang)
    if path is None:
        raise ValueError("Unsupported guide language")
    return json.loads(path.read_text(encoding="utf-8"))
