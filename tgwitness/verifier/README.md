# Verifier sources

These modules assemble into the standalone `../verify.py`. Build with
`python tools/build_standalone_verifier.py`; use `--check` to detect drift.
The builder uses only the standard library and a fixed module order. Its header
hash covers the UTF-8 sources with LF line endings. It removes internal imports
and export declarations without rewriting function bodies or signed formats.

`common`, `chain` and `journal` hold archive bounds, canonical encoding and
signature checks. Other modules separate timestamps, coverage, reports, exports,
witnesses and the console. `timestamps` also checks Intel TDX quotes offline against
the pinned Intel SGX Root CA. Deferred internal imports make dependencies explicit
without an import cycle. Run the CLI through the assembled artifact, which retains
the original shared namespace and command-line limits.

The CLI separates argument handling, archive dispatch and output. Account and
disclosure checks separate manifest, record and coverage validation while retaining
the existing result dictionaries. Differential tests compare the old verifier's
successful results and rejection reasons against both source and assembled checks.
Keep old archives and their embedded verifier for compatibility in both directions.
An embedded verifier still needs an independently trusted source or hash.

`password` opens optional `.tgwpw` exports before ordinary evidence verification.
The wire format is `TGWPW1\n`, a 16-byte salt, an 8-byte nonce prefix, then
big-endian 32-bit lengths and AES-GCM ciphertext/tag records. Counter zero encrypts
the UTF-8 inner filename with AAD `tgwitness-password-v1|name`. Data counters start
at one; their AAD is `tgwitness-password-v1|` + filename + `|more` or `|last`.
A short final record is mandatory, including an empty record after exact 1 MiB
multiples. Decryption rejects trailing data and never publishes partial plaintext.
