"""English research page and its explicitly selected, data-only review materials."""
import json

PATH = "docs/export-clinic/"
TITLE = "Export Clinic"
DESCRIPTION = "Watch a controlled Telegram Desktop export experiment, compare seven test conversations, and inspect the original recording and paired files."
KEYWORDS = "Telegram Desktop HTML JSON export local modification provenance experiment video hash signature"
DOWNLOAD_BASE = "https://phishdestroy.io/research/telegram-export/2026-11-03/"
DOWNLOADS = (
    "export-clinic-paired-files.zip", "export-clinic-review-package.zip",
    "ExportClinic_2026-11-03_12-50-40.mkv", "export-clinic-2min.mp4", "export-clinic-full.mp4",
)
FILES = (
    "comparison-poster.jpg", "article-en.md", "comparison-data.json",
    "review-file-manifest.json", "publication-review.json", "REVIEW_README.md",
    "original-metadata-notes.md", "original-metadata-audit.json",
    "recording-manifest.json", "download-manifest.json", "SHA256SUMS.txt",
    *(f"assets/comparisons/{case}-{version}.jpg"
      for case in ("personal", "private-channel", "private-group", "private-supergroup", "public-channel", "public-supergroup")
      for version in ("before", "modified")),
)
STATIC = {f"assets/export-clinic/{name}": f"website/export-clinic/media/{name}" for name in FILES}
STATIC.update({f"export-clinic.{ext}": f"website/export-clinic/export-clinic.{ext}" for ext in ("css", "js")})


def content(read_public, render, values, json_script):
    template = read_public("website/export-clinic/page.html").decode("utf-8")
    data = json.loads(read_public("website/export-clinic/media/comparison-data.json"))
    return render(template, {**values, "DOWNLOAD_BASE": DOWNLOAD_BASE}) + '<script type="application/json" id="comparison-data">' + json_script(data) + '</script>'
