import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_checks as checks

REVISION = "a" * 40


def run(**values):
    return {"head_sha": REVISION, "head_branch": "main", "event": "push",
            "head_repository": {"full_name": checks.REPOSITORY}, "run_number": 10,
            "run_attempt": 1, "status": "completed", "conclusion": "success",
            "html_url": "https://github.com/phishdestroy/TgWitness/actions/runs/10", **values}


def reader(runs=None, current=REVISION):
    runs = runs or {name: [run()] for name in checks.REQUIRED}
    def read(path):
        if path == "commits/main":
            return {"sha": current}
        workflow = path.split("/")[2]
        return {"workflow_runs": runs.get(workflow, [])}
    return read


class InstallerChecksTests(unittest.TestCase):
    def test_exact_revision_passes_and_optional_path_filtered_check_can_be_absent(self):
        self.assertEqual(checks.qualification(REVISION, reader()), ("passed", []))

    def test_wrong_revision_branch_event_or_repository_cannot_qualify(self):
        for change in ({"head_sha": "b" * 40}, {"head_branch": "feature"}, {"event": "pull_request"},
                       {"head_repository": {"full_name": "someone/fork"}}):
            with self.subTest(change=change):
                read = reader({name: [run(**change)] for name in checks.REQUIRED})
                self.assertEqual(checks.qualification(REVISION, read)[0], "waiting")

    def test_newer_failure_or_rerun_never_reuses_an_older_success(self):
        for change in ({"run_number": 11}, {"run_attempt": 2}):
            with self.subTest(change=change):
                read = reader({"checks.yml": [run(), run(conclusion="failure", **change)]})
                with self.assertRaisesRegex(ValueError, "publication refused"):
                    checks.qualification(REVISION, read)

    def test_queued_and_in_progress_runs_are_not_passed(self):
        for status in ("queued", "in_progress", "waiting"):
            with self.subTest(status=status):
                read = reader({name: [run(status=status, conclusion=None)] for name in checks.REQUIRED})
                self.assertEqual(checks.qualification(REVISION, read)[0], "waiting")

    def test_skipped_cancelled_and_failed_checks_block_publication(self):
        for conclusion in ("failure", "cancelled", "skipped", "neutral", "timed_out", None):
            with self.subTest(conclusion=conclusion):
                read = reader({"checks.yml": [run(conclusion=conclusion)]})
                with self.assertRaisesRegex(ValueError, "publication refused"):
                    checks.qualification(REVISION, read)

    def test_optional_run_must_pass_if_started(self):
        runs = {name: [run()] for name in checks.REQUIRED}
        runs["sealed-checks.yml"] = [run(status="queued", conclusion=None)]
        self.assertEqual(checks.qualification(REVISION, reader(runs))[0], "waiting")
        runs["sealed-checks.yml"] = [run(conclusion="failure")]
        with self.assertRaisesRegex(ValueError, "sealed-checks.yml"):
            checks.qualification(REVISION, reader(runs))

    def test_obsolete_build_is_skipped_without_waiting_for_cancelled_checks(self):
        self.assertFalse(checks.wait(REVISION, read=reader(current="b" * 40)))

    def test_missing_required_check_times_out_instead_of_publishing(self):
        now = [0]
        with self.assertRaisesRegex(TimeoutError, "unchanged"):
            checks.wait(REVISION, timeout=30, read=reader({"checks.yml": [run()]}),
                        clock=lambda: now[0], sleep=lambda delay: now.__setitem__(0, now[0] + delay))
        self.assertEqual(now[0], 30)

    def test_wait_rechecks_until_success(self):
        now = [0]
        def read(path):
            return reader({name: [run(status="queued", conclusion=None)] for name in checks.REQUIRED}
                          if now[0] == 0 else None)(path)
        self.assertTrue(checks.wait(REVISION, timeout=30, read=read, clock=lambda: now[0],
                                   sleep=lambda delay: now.__setitem__(0, now[0] + delay)))
        self.assertEqual(now[0], 15)

    def test_api_failure_does_not_publish(self):
        def broken(path):
            raise OSError("synthetic API outage")
        with self.assertRaises(OSError):
            checks.wait(REVISION, read=broken)


if __name__ == "__main__":
    unittest.main()
