"""Wait for the exact main revision to pass CI before publishing its installer."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time

REPOSITORY = "phishdestroy/TgWitness"
REQUIRED = ("checks.yml", "security-audit.yml")
OPTIONAL = ("sealed-checks.yml",)


def api(path):
    result = subprocess.run(["gh", "api", "repos/" + REPOSITORY + "/" + path],
                            check=True, capture_output=True, text=True, timeout=60)
    return json.loads(result.stdout)


def latest_run(data, revision):
    runs = [run for run in data["workflow_runs"]
            if run.get("head_sha") == revision and run.get("head_branch") == "main"
            and run.get("event") == "push"
            and (run.get("head_repository") or {}).get("full_name") == REPOSITORY]
    return max(runs, key=lambda run: (run["run_number"], run.get("run_attempt", 1)), default=None)


def qualification(revision, read=api):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Expected a full source revision")
    if read("commits/main")["sha"] != revision:
        return "obsolete", []
    pending = []
    for workflow in (*REQUIRED, *OPTIONAL):
        data = read(f"actions/workflows/{workflow}/runs?branch=main&event=push&head_sha={revision}&per_page=100")
        run = latest_run(data, revision)
        if run is None:
            if workflow in REQUIRED:
                pending.append(workflow + ": not started")
            continue
        if run["status"] != "completed":
            pending.append(workflow + ": " + run["status"])
        elif run["conclusion"] != "success":
            raise ValueError(f"Installer publication refused: {workflow}: {run['conclusion']} ({run['html_url']})")
    return ("waiting" if pending else "passed"), pending


def wait(revision, timeout=2700, interval=15, *, read=api, clock=time.monotonic, sleep=time.sleep):
    deadline, previous = clock() + timeout, None
    while True:
        status, pending = qualification(revision, read)
        message = status + (": " + "; ".join(pending) if pending else "")
        if message != previous:
            print("Installer checks: " + message, flush=True)
            previous = message
        if status != "waiting":
            return status == "passed"
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError("Installer checks did not finish; the published installer is unchanged")
        sleep(min(interval, remaining))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--timeout", type=int, default=2700)
    args = parser.parse_args()
    if not 0 <= args.timeout <= 2700:
        parser.error("Timeout must be between 0 and 2700 seconds")
    passed = wait(args.revision, args.timeout)
    if os.environ.get("GITHUB_OUTPUT"):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write("publish=" + str(passed).lower() + "\n")


if __name__ == "__main__":
    main()
