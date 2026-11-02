"""Descriptive statistics must retain scope, unknowns, UTC semantics and signed bytes."""
import json
from pathlib import Path
import sys
import tempfile
from unittest import TestCase, main
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import evidence, report, snapshot_analytics as stats
from tgwitness.report_studio import preview
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_bundle


class AnalyticsTests(TestCase):
    def test_observations_are_not_unique_messages_or_edit_authors(self):
        rows = [{"kind": kind, "observed_at": "2026-10-05T01:30:00+02:00", "chat_id": 1, "message_id": 2,
                 "payload": {"sender_id": 3, "sender_observation": {"display_name": "Same sender"}}}
                for kind in ("message.new", "message.snapshot", "message.edited", "message.deleted", "collector.heartbeat")]
        data = stats.collect(rows)
        self.assertEqual((data["records"], data["messages"]), (5, 2))
        self.assertEqual(data["activity"], [{"from": "2026-10-04", "to": "2026-10-04", "count": 2}])
        self.assertEqual(data["heatmap"][6][23], 2)
        self.assertEqual(data["participants"][0]["count"], 2)
        self.assertEqual(sum(row["count"] for row in data["composition"]), 5)

    def test_missing_dates_and_sender_ids_remain_explicit(self):
        data = stats.collect([{"date": value, "from_id": None} for value in (None, "bad", "2026-01-01T09:00:00")], "snapshot")
        self.assertEqual(data["undated"], 3)
        self.assertEqual(data["activity"], [])
        self.assertEqual(data["participants"], [{"id": None, "label": stats.UNKNOWN, "count": 3}])
        self.assertEqual(sum(sum(day) for day in data["heatmap"]), 0)

    def test_ranking_reconciles_other_and_unknown(self):
        data = stats.collect([{"from_id": i % 13 or None, "date": "2026-01-01T09:00:00Z"} for i in range(120)], "snapshot")
        ranked = stats.ranking(data, "participants", 5)
        self.assertEqual(sum(row["count"] for row in ranked), 120)
        self.assertIn(stats.UNKNOWN, [row["label"] for row in ranked])
        self.assertIn(stats.OTHER, [row["label"] for row in ranked])

    def test_bounded_cardinality_is_declared_and_not_lost(self):
        with patch.object(stats, "LIMIT", 3):
            data = stats.collect([{"date": f"2026-01-{i+1:02d}T00:00:00Z", "from_id": i} for i in range(9)], "snapshot")
        self.assertEqual(data["unlisted"]["activity"], 6)
        self.assertEqual(data["unlisted"]["participants"], 6)
        self.assertEqual(sum(row["count"] for row in stats.ranking(data, "participants", 5)), 9)
        self.assertEqual(sum(row["count"] for row in data["activity"]) + data["unlisted"]["activity"], 9)

    def test_sharing_uses_only_transformed_rows_and_escapes_names(self):
        data = stats.collect([{"chat": {"id": "chat-alias", "title": "Public chat"},
            "message": {"from_id": "participant-alias", "sender": '<img src=x onerror="alert(1)">', "date": "2026-01-01T00:00:00Z"},
            "source": {"name": "PRIVATE_NAME", "id": 99999}}], "sharing")
        document = stats.html_section(data, {}, report.Words("en"))
        self.assertNotIn("PRIVATE_NAME", document)
        self.assertNotIn("99999", json.dumps(data))
        self.assertNotIn("<img", document)
        self.assertIn("&lt;img", document)
        self.assertEqual(data["participants"][0]["id"], "participant-alias")

    def test_utc_bin_totals_and_source_order_independence(self):
        rows = [{"date": f"2025-{month:02d}-01T12:00:00Z", "from_id": 1} for month in range(1, 13)]
        forward, backward = stats.collect(rows, "snapshot"), stats.collect(rows[::-1], "snapshot")
        self.assertEqual(forward, backward)
        self.assertLessEqual(len(forward["activity"]), 90)
        self.assertEqual(sum(row["count"] for row in forward["activity"]), 12)
        extreme = stats.collect([{"date": date} for date in ("0001-01-01T00:00:00Z", "9999-12-31T23:00:00Z")], "snapshot")
        self.assertEqual(sum(row["count"] for row in extreme["activity"]), 2)

    def test_preview_is_bounded_readonly_and_analytics_are_signed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault, store = Vault(root), Store(root)
            store.bind(vault)
            try:
                for number in range(4):
                    store.append("message.new", {"text": "Fictional", "sender_id": number}, 100, number)
                original = report.saved(store).model_dump()
                options = {**report.resolved(store), "design": "editorial", "timeline": False}
                with patch("tgwitness.report_studio.PREVIEW_LIMIT", 2):
                    rendered = preview(store, options)
                self.assertTrue(rendered["sampled"])
                self.assertEqual(rendered["records"], 2)
                self.assertIn("NOT SIGNED", rendered["html"])
                self.assertNotIn("<script", rendered["html"])
                self.assertIn('data-report-template="dossier"', rendered["html"])
                ordered = preview(store, {**options, "template": "activity", "review_findings": "Authored finding"})["html"]
                self.assertLess(ordered.index('id="report-analytics"'), ordered.index('id="examination"'))
                self.assertEqual(original, report.saved(store).model_dump())
                bundle = evidence.export_file(store, vault, "zip", options)
                self.assertTrue(verify_bundle(bundle, fingerprint(vault.public_key))["key_pinned"])
                with zipfile.ZipFile(bundle) as source:
                    data = json.loads(source.read("report.json"))["report"]
                    self.assertEqual(data["analytics"], json.loads(source.read("analytics.json")))
                    self.assertEqual(data["analytics"]["message_observations"], 4)
                    broken = root / "tampered.zip"
                    with zipfile.ZipFile(broken, "w") as out:
                        for name in source.namelist():
                            out.writestr(name, b'{}' if name == "analytics.json" else source.read(name))
                with self.assertRaises(ValueError):
                    verify_bundle(broken, fingerprint(vault.public_key))
            finally:
                store.close()


if __name__ == "__main__":
    main()
