import hashlib
import json
import zipfile

import pytest

from tools.build_source import FILES as SOURCE_FILES
from tools.build_wiki import FILES, PAGES, build_wiki


@pytest.fixture
def wiki_tree(tmp_path):
    for name in SOURCE_FILES:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("Public fixture\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n', encoding="utf-8")
    wiki = tmp_path / "docs/wiki"
    wiki.mkdir(parents=True)
    for name in FILES:
        (wiki / name).write_text("# " + name.removesuffix(".md") + "\n\n[Home](Home.md)\n", encoding="utf-8")
    return tmp_path


def test_wiki_bundle_has_only_reviewed_pages_and_matching_hashes(wiki_tree):
    extra = wiki_tree / "docs/wiki/unreviewed.md"
    extra.write_text("Do not publish this page", encoding="utf-8")
    result = build_wiki(wiki_tree)
    assert result["pages"] == len(PAGES) == 18
    assert result["language"] == "en"
    output = wiki_tree / "dist"
    archive_path = output / result["archive"]
    assert hashlib.sha256(archive_path.read_bytes()).hexdigest() == result["sha256"]
    assert json.loads((output / "wiki-manifest.json").read_text()) == result
    assert archive_path.with_suffix(".zip.sha256").read_text().split()[0] == result["sha256"]
    with zipfile.ZipFile(archive_path) as archive:
        assert set(archive.namelist()) == set(FILES)
        assert {p.name for p in (output / "wiki").iterdir()} == set(FILES)
        for name, digest in result["files"].items():
            data = archive.read(name)
            assert data == (output / "wiki" / name).read_bytes()
            assert hashlib.sha256(data).hexdigest() == digest
    assert extra.read_text() == "Do not publish this page"


def test_wiki_rewrites_page_document_and_image_links_for_forks(wiki_tree):
    (wiki_tree / "docs/reference.md").write_text("# Reference\n", encoding="utf-8")
    assets = wiki_tree / "docs/assets"
    assets.mkdir()
    (assets / "demo.png").write_bytes(b"synthetic image")
    (assets / "static.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"/>', encoding="utf-8")
    (wiki_tree / "docs/wiki/Home.md").write_text(
        '[Start](Getting-Started.md#install)\n[Reference](../reference.md)\n'
        '![Demo](../assets/demo.png "Fictional data")\n[External](https://example.org/docs)\n'
        '[Full size](../assets/demo.png)\n[Static diagram](../assets/static.svg)\n'
        '[Section](#section)\n~~~md\n[Example](missing.md)\n~~~\n',
        encoding="utf-8")
    build_wiki(wiki_tree, repository="example/Project", branch="release")
    page = (wiki_tree / "dist/wiki/Home.md").read_text(encoding="utf-8")
    assert "[Start](https://github.com/example/Project/wiki/Getting-Started#install)" in page
    assert "[Reference](https://github.com/example/Project/blob/release/docs/reference.md)" in page
    assert '![Demo](https://github.com/example/Project/wiki/assets/demo.png "Fictional data")' in page
    assert "[Full size](https://github.com/example/Project/wiki/assets/demo.png)" in page
    assert "[Static diagram](https://github.com/example/Project/wiki/assets/static.svg)" in page
    assert (wiki_tree / "dist/wiki/assets/demo.png").read_bytes() == b"synthetic image"
    manifest = json.loads((wiki_tree / "dist/wiki-manifest.json").read_text())
    assert manifest["assets"] == 2
    with zipfile.ZipFile(wiki_tree / "dist" / manifest["archive"]) as archive:
        assert archive.read("assets/demo.png") == b"synthetic image"
        assert archive.read("assets/static.svg") == (assets / "static.svg").read_bytes()
    assert "[External](https://example.org/docs)" in page
    assert "[Section](#section)" in page
    assert "~~~md\n[Example](missing.md)\n~~~" in page


def test_wiki_bundles_film_preview_and_keeps_download_in_source_repository(wiki_tree):
    assets = wiki_tree / "docs/assets/presentation"
    assets.mkdir(parents=True)
    preview = b"synthetic film preview"
    (assets / "investigation.gif").write_bytes(preview)
    (assets / "investigation.mp4").write_bytes(b"synthetic film")
    (wiki_tree / "docs/wiki/Home.md").write_text(
        "![Case preview](../assets/presentation/investigation.gif)\n"
        "[Download MP4](../assets/presentation/investigation.mp4)\n", encoding="utf-8")

    result = build_wiki(wiki_tree, repository="example/Project", branch="release")
    page = (wiki_tree / "dist/wiki/Home.md").read_text(encoding="utf-8")
    assert page == (
        "![Case preview](https://github.com/example/Project/wiki/assets/presentation/investigation.gif)\n"
        "[Download MP4](https://github.com/example/Project/blob/release/docs/assets/presentation/investigation.mp4)\n")
    with zipfile.ZipFile(wiki_tree / "dist" / result["archive"]) as archive:
        assert archive.read("assets/presentation/investigation.gif") == preview
        assert not any(name.endswith(".mp4") for name in archive.namelist())


def test_wiki_bundles_picture_sources_and_fallback_for_a_fork(wiki_tree):
    assets = wiki_tree / "docs/assets"
    assets.mkdir()
    (assets / "still.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"/>', encoding="utf-8")
    (assets / "motion.webp").write_bytes(b"synthetic animation")
    source = (
        '<picture>\n<source media="(prefers-reduced-motion: reduce)" srcset="../assets/still.svg">\n'
        '<img src="../assets/motion.webp" alt="Observation journal">\n</picture>\n'
        '<img src="https://example.org/external.webp">\n'
        '```html\n<img src="missing.webp">\n```\n'
    )
    (wiki_tree / "docs/wiki/Home.md").write_text(source, encoding="utf-8")
    result = build_wiki(wiki_tree, repository="example/Project")
    rendered = (wiki_tree / "dist/wiki/Home.md").read_text(encoding="utf-8")
    assert 'srcset="https://github.com/example/Project/wiki/assets/still.svg"' in rendered
    assert 'src="https://github.com/example/Project/wiki/assets/motion.webp"' in rendered
    assert 'src="https://example.org/external.webp"' in rendered
    assert '```html\n<img src="missing.webp">\n```' in rendered
    assert result["assets"] == 2
    assert (wiki_tree / "dist/wiki/assets/motion.webp").read_bytes() == b"synthetic animation"


@pytest.mark.parametrize("attribute", [
    'src="../../data/private.webp"',
    'srcset="../assets/missing.svg"',
    'src="../../README.md"',
    'srcset="../assets/one.webp 1x, ../assets/two.webp 2x"',
])
def test_wiki_picture_refuses_unreviewed_or_ambiguous_sources(wiki_tree, attribute):
    (wiki_tree / "docs/wiki/Home.md").write_text('<picture><img ' + attribute + '></picture>', encoding="utf-8")
    with pytest.raises(ValueError):
        build_wiki(wiki_tree)
    assert not (wiki_tree / "dist").exists()


@pytest.mark.parametrize("target", ["missing.md", "../../data/private.md", "../../../outside.md"])
def test_wiki_refuses_missing_or_private_link_targets(wiki_tree, target):
    data = wiki_tree / "docs/data"
    data.mkdir()
    (data / "private.md").write_text("Not public", encoding="utf-8")
    private = wiki_tree / "data"
    private.mkdir()
    (private / "private.md").write_text("Not public", encoding="utf-8")
    (wiki_tree / "docs/wiki/Home.md").write_text("[Bad](" + target + ")\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not a public source file"):
        build_wiki(wiki_tree)
    assert not (wiki_tree / "dist").exists()


def test_wiki_refuses_unrelated_output_without_overwriting_it(wiki_tree):
    output = wiki_tree / "dist/wiki"
    output.mkdir(parents=True)
    (output / "private.txt").write_text("Keep this file", encoding="utf-8")
    (output / "Home.md").write_text("Old reviewed page", encoding="utf-8")
    with pytest.raises(ValueError, match="Unexpected or linked"):
        build_wiki(wiki_tree)
    assert (output / "private.txt").read_text() == "Keep this file"
    assert (output / "Home.md").read_text() == "Old reviewed page"


def test_wiki_requires_every_navigation_page(wiki_tree):
    (wiki_tree / "docs/wiki/FAQ.md").unlink()
    with pytest.raises(ValueError, match="Missing or linked wiki input: FAQ.md"):
        build_wiki(wiki_tree)


def test_wiki_rejects_unreviewed_nested_asset_without_overwriting(wiki_tree):
    output = wiki_tree / "dist/wiki/assets"
    output.mkdir(parents=True)
    (output / "private.svg").write_text("Keep this file", encoding="utf-8")
    with pytest.raises(ValueError, match="Unexpected or linked"):
        build_wiki(wiki_tree)
    assert (output / "private.svg").read_text() == "Keep this file"


def test_wiki_rejects_non_image_sources_used_as_images(wiki_tree):
    (wiki_tree / "docs/wiki/Home.md").write_text("![Wrong](../../README.md)\n", encoding="utf-8")
    with pytest.raises(ValueError, match="reviewed documentation asset"):
        build_wiki(wiki_tree)


@pytest.mark.parametrize("settings", [
    {"repository": "../private"},
    {"repository": "https://github.com/example/project"},
    {"branch": "../../private"},
])
def test_wiki_rejects_invalid_destination_parameters(wiki_tree, settings):
    with pytest.raises(ValueError):
        build_wiki(wiki_tree, **settings)
