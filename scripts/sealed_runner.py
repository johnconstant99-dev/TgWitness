"""Standard-library supervisor for the pinned GitHub-hosted reusable workflow.

Never reads a caller checkout, downloads caller artifacts, restores caches, or
passes GitHub credentials into the public-facing container. Only encrypted files
are copied to public/. All commands use argument lists, never shell expansion.
"""
import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

TUNNEL_IMAGE = "cloudflare/cloudflared@sha256:4955524aeaa379e154023d5a027c250f7b35041a2e7e950cf13f144bc9b9c5ba"
ROOT = Path(__file__).resolve().parents[1]


def command(args, timeout=120, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("Runner command failed: " + args[0])
    return result.stdout.strip()


def location():
    if sys.platform != "linux" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("This supervisor requires a GitHub-hosted Linux runner")
    run, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch(r"[0-9]{1,24}", run) or not re.fullmatch(r"[0-9]{1,8}", attempt):
        raise ValueError("Invalid GitHub run identity")
    parent = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    name = "tgwitness-sealed-" + run + "-" + attempt
    directory = parent / name
    if directory.is_symlink() or directory.resolve().parent != parent:
        raise ValueError("Unexpected session directory")
    return directory, name


def write(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(value, out)


def restrictions():
    return ["--user", str(os.getuid()) + ":" + str(os.getgid()), "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=256",
            "--memory=2g", "--cpus=2", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m"]


def helper(directory, name, arguments, extra_mounts=()):
    return command(["docker", "run", "--rm", "--network=none", *restrictions(),
        "--mount", f"type=bind,src={directory / 'config'},dst=/config,readonly",
        "--mount", f"type=bind,src={directory / 'out'},dst=/output", *extra_mounts,
        name, "python", "-m", "tgwitness.sealed_package", *arguments], timeout=600)


def start():
    directory, name = location()
    minutes = os.environ.get("SESSION_MINUTES", "30")
    if not re.fullmatch(r"[0-9]{1,3}", minutes) or not 10 <= int(minutes) <= 120:
        raise ValueError("Session duration must be 10..120 minutes")
    recipient = os.environ.get("RECIPIENT", "")
    if not re.fullmatch(r"[A-Za-z0-9+/]{500,1500}={0,2}", recipient):
        raise ValueError("Paste the public recipient from the setup helper")
    directory.mkdir(mode=0o700)  # Refuse a prepopulated workspace, including reruns.
    for part in ("config", "data", "out", "public"):
        (directory / part).mkdir(mode=0o700)
    commit = command(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid trusted checkout")
    config = {"token": secrets.token_urlsafe(32), "recipient": recipient, "seconds": int(minutes) * 60,
        "context": {"collector_sha": commit, "repository": os.environ["GITHUB_REPOSITORY"],
                    "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"]}}
    write(directory / "config" / "session.json", config)
    command(["docker", "build", "--no-cache", "--file", str(ROOT / "deploy" / "Dockerfile.sealed"),
             "--tag", name, str(ROOT)], timeout=900)
    command(["docker", "network", "create", name])
    command(["docker", "run", "--detach", "--name", name, "--network", name, "--network-alias", "collector",
        *restrictions(), "--mount", f"type=bind,src={directory / 'config'},dst=/config,readonly",
        "--mount", f"type=bind,src={directory / 'data'},dst=/data",
        "--mount", f"type=bind,src={directory / 'out'},dst=/output", name])
    # Wait for the API to be listening before publishing a connection artifact.
    deadline = time.monotonic() + 90
    while True:
        try:
            command(["docker", "exec", name, "python", "-c",
                     "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/', timeout=2)"], timeout=5)
            break
        except RuntimeError:
            if time.monotonic() > deadline:
                raise RuntimeError("Collector failed to start") from None
            time.sleep(1)
    command(["docker", "run", "--detach", "--name", name + "-tunnel", "--network", name,
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=256m",
        TUNNEL_IMAGE, "tunnel", "--no-autoupdate", "--url", "http://collector:8787"], timeout=180)
    deadline = time.monotonic() + 90
    while True:
        # cloudflared prints its URL to stderr. Never relay its full logs to GitHub.
        result = subprocess.run(["docker", "logs", name + "-tunnel"], capture_output=True, text=True, timeout=10)
        match = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", result.stdout + result.stderr)
        if match:
            break
        if time.monotonic() > deadline:
            raise RuntimeError("Tunnel failed to start")
        time.sleep(1)
    helper(directory, name, ["connection", "--config", "/config/session.json", "--url", match.group(),
                            "--out", "/output/connection.tgwsealed"])
    shutil.move(str(directory / "out" / "connection.tgwsealed"), directory / "public" / "connection.tgwsealed")
    print("Encrypted connection is ready. Download the sealed-connection artifact and open it in the helper.")


def wait():
    directory, name = location()
    config = json.loads((directory / "config" / "session.json").read_bytes())
    deadline = time.monotonic() + config["seconds"] + 600
    result = directory / "out" / "result.json"
    while not result.exists():
        if time.monotonic() > deadline:
            raise RuntimeError("Capture exceeded its deadline")
        if command(["docker", "inspect", "--format", "{{.State.Running}}", name]) != "true":
            raise RuntimeError("Capture stopped before producing a result")
        time.sleep(2)
    # All network-facing processes stop BEFORE the attestation step sees the ZIP.
    command(["docker", "rm", "--force", name + "-tunnel"], check=False)
    command(["docker", "stop", "--time", "40", name], timeout=60, check=False)
    if json.loads(result.read_bytes()) != {"phase": "sealed"}:
        raise RuntimeError("Capture was cancelled or failed; no result will be uploaded")
    evidence = directory / "out" / "evidence.zip"
    if evidence.is_symlink() or not evidence.is_file():
        raise RuntimeError("No regular evidence file")
    print("Collector stopped. The fixed evidence file is ready for attestation.")


def pack():
    directory, name = location()
    # This path comes from the pinned attest action's output, never a workflow input.
    bundle = Path(os.environ["ATTESTATION_BUNDLE"]).resolve(strict=True)
    parent = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if not bundle.is_relative_to(parent) or bundle.is_symlink() or bundle.stat().st_size > 16 * 1024**2:
        raise ValueError("Unexpected attestation bundle")
    shutil.copyfile(bundle, directory / "out" / "attestation.jsonl")
    helper(directory, name, ["package", "--config", "/config/session.json", "--out", "/output",
                            "--attestation", "/output/attestation.jsonl"])
    shutil.move(str(directory / "out" / "delivery.tgwsealed"), directory / "public" / "delivery.tgwsealed")
    print("Encrypted result is ready. No plaintext archive is uploaded.")


def cleanup():
    directory, name = location()
    command(["docker", "stop", "--time", "40", name], timeout=60, check=False)
    command(["docker", "rm", "--force", name, name + "-tunnel"], check=False)
    command(["docker", "network", "rm", name], check=False)
    # Keep only explicitly encrypted public artifacts. No shred/physical-erasure claim.
    for part in ("data", "config", "out"):
        target = directory / part
        if target.is_symlink() or target.resolve().parent != directory.resolve():
            raise ValueError("Refusing unexpected cleanup path")
        if target.exists():
            shutil.rmtree(target)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("start", "wait", "pack", "cleanup"))
    args = parser.parse_args()
    try:
        {"start": start, "wait": wait, "pack": pack, "cleanup": cleanup}[args.command]()
    except Exception as exc:
        parser.exit(1, "Sealed runner failed: " + type(exc).__name__ + ". No private diagnostics published.\n")


if __name__ == "__main__":
    main()
