# Handoff translation provenance — 2026-11-01

English remains the canonical interface and report source. This update used the
DeepL API to translate static workflow, account-export, sharing-copy and recipient
report labels, including acquisition limitations and disclosure warnings. It also
replaced English-valued entries used by those active flows. Existing translations
were preserved. Captured messages, account data, collection purposes and other
user-supplied values were not submitted for translation.

## Provider and languages

DeepL's live [Languages API](https://developers.deepl.com/docs/languages/using-the-languages-api)
reported all 24 target locales as stable text-translation targets. Requests used
English as the source, the quality-optimized model, static interface context, and
[tag handling](https://developers.deepl.com/api-reference/translate/request-translation)
to protect literals. Optional style instructions were used where accepted;
Thai requests omitted that unsupported option.

Targets: Arabic, Bengali, German, Spanish, Persian, French, Hebrew, Hindi,
Indonesian, Italian, Japanese, Korean, Malay, Polish, Brazilian Portuguese,
Russian, Thai, Turkish, Ukrainian, Urdu, Uzbek, Vietnamese, Simplified Chinese
and Traditional Chinese. Together with English, these preserve the application's
25-language selection.

Translations were supplied by DeepL. Processing only restored protected literals,
removed transport markup and escaped HTML. Responses with missing placeholders
were rejected and retried. Meaningful English outputs were also retried. DeepL
retained some cognates, product names and unit expressions; the Thai category
label `Stories` remained unchanged after targeted retries.

## Validation

- All 3,371 required scanner, static-page and compatibility keys are present in
  each of the 24 dictionaries; English still resolves directly to its source.
- The update changes 9,483 entries across 407 distinct English source keys.
- Every preexisting non-English-valued translation remains unchanged.
- All changed entries preserve placeholder counts and HTML tags and attributes.
- Referenced filenames and the verification identifier `TRUSTED_SHA256` are
  preserved, with no translation-protection tokens left in the output.
- All five account-acquisition limitations and all five disclosure warnings have
  translated values in every target dictionary.
- Locale JSON parsing and `git diff --check` pass.

English fallback behavior remains available for future missing keys. Original
message content and signed payloads continue to be displayed as captured.
