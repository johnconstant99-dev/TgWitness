"""Run explicit independent CI checks, with bounded concurrency and durable results.

Each check runs in its own process and temporary directory. No shell or wildcard
discovery is used. Failure does not prevent the remaining checks from running.
Timeout cleanup has a five-second budget. Process-tree termination is best
effort; a descendant that detaches itself may survive, but cannot hold the runner
open through an inherited output pipe.
"""
import argparse
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MAX_LOG_BYTES = 4 * 1024**2
SUITES = {
    "browser": (
        "check_session_reservations.py", "check_account_recovery.py",
        "check_browser.py", "check_mcp_transport.py", "check_integrations_browser.py",
        "check_mcp_browser.py", "check_settings_browser.py", "check_analysis_browser.py",
        "check_account_browser.py", "check_fleet_browser.py", "check_proxy_async_browser.py",
        "check_export_async_browser.py", "check_account_export_browser.py", "check_refresh_browser.py",
        "check_account_reports.py",
        "check_analyst_browser.py", "check_history_browser.py", "check_sealed_browser.py",
        "check_interactions_browser.py", "check_workspace_browser.py", "check_quick_browser.py",
        "check_proof_browser.py", "check_setup_browser.py", "check_public_proxies_browser.py",
        "check_capture_language_browser.py",
    ),
    "browser-ux": (
        "check_workflows_browser.py", "check_disclosure_preview_browser.py", "check_handoff_languages_browser.py",
        "check_router_browser.py", "check_view_host_browser.py", "check_view_lifecycle_browser.py",
        "check_polling_browser.py", "check_time_browser.py", "check_shell_browser.py",
        "check_health_controls_browser.py", "check_notifications_browser.py",
        "check_chat_layout_browser.py", "check_chat_list_browser.py", "check_chat_features_browser.py",
        "check_sources_browser.py", "check_parameters_browser.py", "check_accounts_overview_browser.py",
        "check_account_states_browser.py",
        "check_access_sections_browser.py", "check_journal_browser.py", "check_exports_browser.py",
        "check_controls_browser.py", "check_quick_search_browser.py",
    ),
    "site": ("check_site.py", "check_docs_site.py", "check_report_example.py"),
}


@dataclass(frozen=True)
class Check:
    name: str
    command: tuple[str, ...]


async def stop_process(process):
    """Stop descendants too: a timed-out check may own a browser and an app."""
    if os.name == "nt":
        killer = await asyncio.create_subprocess_exec(
            str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/taskkill.exe"),
            "/PID", str(process.pid), "/T", "/F",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        try:
            await asyncio.wait_for(killer.wait(), 2)
        except TimeoutError:
            killer.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        # Also kill descendants that ignored TERM, even if their parent exited.
        try:
            await asyncio.wait_for(process.wait(), 2)
        except TimeoutError:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.returncode is None:
        process.kill()
    try:
        await asyncio.wait_for(process.wait(), 1)
    except TimeoutError:
        pass


async def finish_output(process, reader, log, result):
    """Escaped descendants must not turn a timeout into an unbounded pipe wait."""
    try:
        result["output_truncated"] = await asyncio.wait_for(asyncio.shield(reader), 2)
    except TimeoutError:
        result["output_interrupted"] = result["output_truncated"] = True
        # asyncio has no public StreamReader.close(). Close its pipe transport.
        # This also releases a pending Windows Proactor pipe read.
        transport = getattr(process.stdout, "_transport", None)
        if transport is not None:
            transport.close()
        reader.cancel()
        try:
            await reader
        except asyncio.CancelledError:
            pass
        log.write(b"\n[output interrupted: a descendant kept the pipe open after termination]\n")


async def capture_output(stream, log):
    """Drain all output, while bounding each artifact and memory consumption."""
    kept = total = 0
    limit = MAX_LOG_BYTES - 256
    while chunk := await stream.read(65536):
        total += len(chunk)
        part = chunk[:max(0, limit - kept)]
        log.write(part)
        log.flush()
        kept += len(part)
    truncated = total > kept
    if truncated:
        log.write(f"\n[output truncated: kept {kept} of {total} bytes]\n".encode())
    return truncated


async def run_one(check, output, timeout, cwd):
    started = time.monotonic()
    result = {"name": check.name, "status": "error", "returncode": None,
              "started_at": datetime.now(timezone.utc).isoformat(),
              "log": check.name + ".log", "output_truncated": False, "output_interrupted": False}
    process = reader = None
    print(f"START {check.name}", flush=True)
    with (output / result["log"]).open("wb") as log:
        try:
            with tempfile.TemporaryDirectory(prefix="ci-check-") as temporary:
                environment = {**os.environ, "TMPDIR": temporary, "TMP": temporary, "TEMP": temporary,
                               "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"}
                kwargs = {"start_new_session": True} if os.name != "nt" else {
                    "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                process = await asyncio.create_subprocess_exec(
                    *check.command, cwd=cwd, env=environment,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, **kwargs)
                reader = asyncio.create_task(capture_output(process.stdout, log))
                try:
                    # Include output draining: orphan children must not hold a pipe forever.
                    await asyncio.wait_for(asyncio.gather(process.wait(), asyncio.shield(reader)), timeout)
                    result["status"] = "passed" if process.returncode == 0 else "failed"
                except TimeoutError:
                    result["status"] = "timed_out"
                    await stop_process(process)
                except asyncio.CancelledError:
                    result["status"] = "cancelled"
                    await stop_process(process)
                    raise
                finally:
                    result["returncode"] = process.returncode
                    await finish_output(process, reader, log, result)
        except OSError as exc:
            log.write((f"Cannot run check: {type(exc).__name__}: {exc}\n").encode("utf-8"))
            if process is not None and process.returncode is None:
                await stop_process(process)
        finally:
            result["duration_seconds"] = round(time.monotonic() - started, 3)
            (output / (check.name + ".json")).write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(f"{result['status'].upper()} {check.name} ({result['duration_seconds']:.1f}s)", flush=True)
    return result


def write_summary(output, results, elapsed, workers):
    passed = all(item["status"] == "passed" for item in results)
    report = {"passed": passed, "workers": workers, "duration_seconds": round(elapsed, 3), "checks": results}
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = ["| Check | Result | Seconds |", "| --- | --- | ---: |"]
    lines.extend(f"| {r['name']} | {r['status']} | {r['duration_seconds']:.1f} |" for r in results)
    lines.append(f"\nElapsed: {elapsed:.1f}s. Logs and per-check JSON: `{output.name}` artifact directory.\n")
    summary = "\n".join(lines)
    (output / "summary.md").write_text(summary, encoding="utf-8")
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a", encoding="utf-8") as destination:
            destination.write(summary + "\n")
    return passed


async def run_checks(checks, output, *, workers=2, timeout=600, cwd=ROOT):
    if workers not in (1, 2) or not math.isfinite(timeout) or timeout <= 0 or not checks or len(checks) > 128:
        raise ValueError("Use one or two workers, a positive timeout and 1–128 explicit checks")
    names = [check.name for check in checks]
    if len(names) != len(set(names)) or any(not re.fullmatch(r"[a-zA-Z0-9_-]+", name) for name in names):
        raise ValueError("Check names must be unique safe filenames")
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    semaphore = asyncio.Semaphore(workers)

    async def limited(check):
        async with semaphore:
            return await run_one(check, output, timeout, cwd)

    started = time.monotonic()
    results = await asyncio.gather(*(limited(check) for check in checks))
    passed = write_summary(output, results, time.monotonic() - started, workers)
    return passed, results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True, choices=SUITES)
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    parser.add_argument("--timeout", type=float, default=600,
                        help="Seconds per check, followed by up to five seconds of cleanup")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    checks = [Check(Path(script).stem, (sys.executable, str(ROOT / "tools" / script)))
              for script in SUITES[args.suite]]
    passed, _ = asyncio.run(run_checks(checks, args.output or ROOT / "build/check-results" / args.suite,
                                      workers=args.jobs, timeout=args.timeout))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
