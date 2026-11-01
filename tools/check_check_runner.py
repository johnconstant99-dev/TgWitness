"""Synthetic regression for concurrency, failure collection, log caps and timeouts."""
import asyncio
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

from run_checks import Check, MAX_LOG_BYTES, ROOT, SUITES, run_checks


async def check_runner():
    with tempfile.TemporaryDirectory(prefix="check-runner-") as scratch:
        directory = Path(scratch)
        # Windows process startup is slower; keep the Linux CI probe inexpensive.
        test_timeout = 10 if os.name == "nt" else 2
        fixture = directory / "fixture.py"
        fixture.write_text('''import json, os, subprocess, sys, time
from pathlib import Path
mode, directory = sys.argv[1], Path(sys.argv[2])
pause = float(sys.argv[3])
if mode == "escaped":
    kwargs = {"start_new_session":True} if os.name != "nt" else {"creationflags":subprocess.CREATE_NEW_PROCESS_GROUP}
    child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"], stdout=sys.stdout, stderr=sys.stderr, **kwargs)
    (directory / "escaped.pid").write_text(str(child.pid))
    print("parent exiting with inherited pipe still open",flush=True)
elif mode == "timeout":
    subprocess.Popen([sys.executable, "-c", "import sys,time;from pathlib import Path;time.sleep(float(sys.argv[2]));Path(sys.argv[1]).write_text('orphan')", str(directory / "orphan.txt"), str(pause + 2)])
    time.sleep(60)
elif mode == "verbose":
    sys.stdout.write("x" * (5 * 1024**2))
elif mode == "failure":
    print("synthetic failure", flush=True)
    raise SystemExit(7)
else:
    start = time.time()
    if mode in ("first", "second"):
        (directory / (mode + ".ready")).touch()
        other = "second" if mode == "first" else "first"
        while not (directory / (other + ".ready")).exists():
            time.sleep(.01)
    time.sleep(.25)
    (directory / (mode + ".json")).write_text(json.dumps({"start":start,"end":time.time(),"temp":os.environ["TMP"]}))
    print("synthetic success", flush=True)
''', encoding="utf-8")
        modes = ("first", "second", "failure", "timeout", "verbose", "last")
        checks = [Check(mode, (sys.executable, str(fixture), mode, str(directory), str(test_timeout))) for mode in modes]
        checks.append(Check("missing", (str(directory / "no-such-executable"),)))
        # A caller's summary is an output file, not a command to execute.
        original = os.environ.get("GITHUB_STEP_SUMMARY")
        os.environ["GITHUB_STEP_SUMMARY"] = str(directory / "github-summary.md")
        try:
            passed, results = await run_checks(checks, directory / "results", timeout=test_timeout)
        finally:
            if original is None:
                os.environ.pop("GITHUB_STEP_SUMMARY", None)
            else:
                os.environ["GITHUB_STEP_SUMMARY"] = original
        assert not passed and len(results) == len(checks)
        by_name = {result["name"]: result for result in results}
        assert by_name["failure"]["status"] == "failed" and by_name["failure"]["returncode"] == 7
        assert by_name["timeout"]["status"] == "timed_out"
        assert by_name["missing"]["status"] == "error"
        assert by_name["last"]["status"] == "passed", "Failures must not skip subsequent checks"
        assert by_name["verbose"]["status"] == "passed" and by_name["verbose"]["output_truncated"]
        assert (directory / "results/verbose.log").stat().st_size <= MAX_LOG_BYTES
        assert "output truncated" in (directory / "results/verbose.log").read_text()
        assert "synthetic failure" in (directory / "results/failure.log").read_text()
        times = [json.loads((directory / (mode + ".json")).read_text()) for mode in ("first", "second", "last")]
        assert max(t["start"] for t in times[:2]) < min(t["end"] for t in times[:2]), "Expected parallel execution"
        assert len({t["temp"] for t in times}) == 3, "Checks must have separate temporary directories"
        events = [(t["start"], 1) for t in times] + [(t["end"], -1) for t in times]
        active = peak = 0
        for _, change in sorted(events):
            active += change
            peak = max(peak, active)
        assert peak == 2, peak
        summary = json.loads((directory / "results/results.json").read_text())
        assert not summary["passed"] and summary["workers"] == 2
        assert len(summary["checks"]) == len(checks)
        assert "timed_out" in (directory / "github-summary.md").read_text()
        assert all((directory / "results" / (item.name + ".json")).is_file() for item in checks)
        await asyncio.sleep(test_timeout + 2.1)
        assert not (directory / "orphan.txt").exists(), "Timeout left a descendant running"

        escaped = Check("escaped", (sys.executable, str(fixture), "escaped", str(directory), str(test_timeout)))
        try:
            passed, result = await run_checks([escaped], directory / "escaped", timeout=test_timeout)
            assert not passed and result[0]["status"] == "timed_out"
            assert result[0]["output_interrupted"], "An inherited pipe must be forcibly closed"
            assert result[0]["duration_seconds"] < test_timeout + 7, "Cleanup exceeded its bounded budget"
        finally:
            # The test deliberately detached this child; clean up only its saved PID.
            if (directory / "escaped.pid").is_file():
                pid = int((directory / "escaped.pid").read_text())
                if os.name == "nt":
                    subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/taskkill.exe"),
                                    "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=5)
                else:
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

        passed, results = await run_checks(checks[:1], directory / "serial", workers=1)
        assert passed and results[0]["status"] == "passed"
        assert json.loads((directory / "serial/results.json").read_text())["workers"] == 1
        for bad in ([Check("../escape", (sys.executable,))], [checks[0], checks[0]]):
            try:
                await run_checks(bad, directory / "invalid")
            except ValueError:
                pass
            else:
                raise AssertionError("Unsafe or duplicate check name accepted")
        for workers, timeout in ((3, 1), (0, 1), (2, 0), (2, float("inf")), (2, float("nan"))):
            try:
                await run_checks(checks[:1], directory / "invalid", workers=workers, timeout=timeout)
            except ValueError:
                pass
            else:
                raise AssertionError("Invalid resource limit accepted")
        for suite in SUITES.values():
            assert len(suite) == len(set(suite))
            assert all((ROOT / "tools" / script).is_file() for script in suite)
        # Exercise the real CLI exit status without changing its production lists.
        (directory / "tools").mkdir()
        (directory / "tools/failure.py").write_text("raise SystemExit(7)\n", encoding="utf-8")
        driver = (
            "import sys;from pathlib import Path;from tools import run_checks as r;"
            "r.ROOT=Path(sys.argv[1]);r.SUITES['browser']=('failure.py',);"
            "sys.argv=['run_checks','--suite','browser'];raise SystemExit(r.main())")
        process = subprocess.run([sys.executable, "-c", driver, str(directory)], cwd=ROOT,
                                 capture_output=True, timeout=60)
        assert process.returncode == 1, process.stderr.decode(errors="replace")
    print("PASS: concurrency=2, all failures collected, bounded logs, timeout tree cleanup, serial mode and invalid limits")


if __name__ == "__main__":
    asyncio.run(check_runner())
