"""A text reader must receive the same instructions and sources as a browser."""
from tools.site_llms import full, markdown


def test_article_export_keeps_commands_tables_nested_steps_and_absolute_sources():
    source = '''<html><head><script>private chrome</script></head><body>
    <nav>Menu text</nav><main><article class="guide-content"><h1>Use the archive</h1>
    <p>Use <code>TGWITNESS_ARCHIVE_TOKEN</code>, not the panel token.</p>
    <ol><li>Install.<ul><li>Choose a virtual environment.</li></ul></li><li>Start.</li></ol>
    <pre><code>python -m tgwitness.mcp_server --api-url http://127.0.0.1:8787


if a &lt; b:
    print("a &amp; b")</code></pre>
    <table><tr><th>Transport</th><th>Guide</th></tr>
    <tr><td>HTTP</td><td><a href="../access/#tokens">Access</a></td></tr></table>
    <details><summary>Limits</summary><p>No Telegram write operations.</p></details>
    <svg><title>Hash chain</title><text>SHA-256</text></svg>
    <button>Copy command</button><script>never include this</script></article>
    <footer>Footer text</footer></main></body></html>'''
    result = markdown(source, "https://example.org/Project/docs/mcp/")
    assert result.startswith("# Use the archive\n\nCanonical page:")
    assert "Use `TGWITNESS_ARCHIVE_TOKEN`, not the panel token." in result
    assert "1. Install." in result and "   - Choose a virtual environment." in result
    assert "2. Start." in result
    assert '8787\n\n\nif a < b:\n    print("a & b")\n```' in result
    assert "| Transport | Guide |\n| --- | --- |" in result
    assert "[Access](https://example.org/Project/docs/access/#tokens)" in result
    assert "**Limits**" in result and "No Telegram write operations." in result
    assert "Hash chain · SHA-256" in result
    for chrome in ("Menu text", "Footer text", "Copy command", "private chrome", "never include this"):
        assert chrome not in result
    assert all(line == line.rstrip(" \t") for line in result.splitlines())
    assert full("# Index\n", [result]).endswith("\n")
    assert not full("# Index\n", [result]).endswith("\n\n")


def test_prose_cleanup_preserves_code_whitespace():
    result = markdown('<main><h1>Copy</h1><blockquote><p>Quote</p><p>More</p></blockquote>'
                      '<ol><li>Run:<pre><code>print("a  ")  \n\nnext()</code></pre></li></ol></main>',
                      "https://example.org/docs/")
    assert 'print("a  ")  \n\n   next()' in result
    assert all(line == line.rstrip(" \t") for line in result.splitlines() if 'print(' not in line)


def test_main_export_preserves_examples_and_uses_html_canonical():
    result = markdown('''<link rel="canonical" href="https://example.org/docs/changelog/">
    <header>Language menu</header><main><h1>Changelog</h1><section><h2>Version</h2>
    <p><a href="https://example.org/source?a=1&amp;b=2">Source</a></p>
    <pre><code>```example</code></pre><a href="javascript:alert(1)">Ignore</a>
    <p aria-hidden="true">Decorative</p></section></main>''', "https://example.org/de/docs/changelog/")
    assert "Canonical page: https://example.org/docs/changelog/" in result
    assert "## Version" in result
    assert "[Source](https://example.org/source?a=1&b=2)" in result
    assert "````\n```example\n````" in result
    assert "Language menu" not in result and "javascript:" not in result and "Decorative" not in result
