"""Reject a release whose GitHub caller still runs a different collector."""
import argparse
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = "phishdestroy/TgWitness/.github/workflows/sealed-collector.yml"
CALLER = ".github/workflows/sealed-witness.yml"
COLLECTOR = ".github/workflows/sealed-collector.yml"
POLICY = "tgwitness/sealed_policy.json"
RUNTIME = ("tgwitness", "tgwitness_capture", "scripts/sealed_runner.py", "deploy/Dockerfile.sealed",
           "addons/capture/deploy/Dockerfile.official", "addons/capture/deploy/official-start.sh",
           "addons/capture/deploy/official-seccomp.json",
           "addons/capture/requirements.lock", "addons/capture/pyproject.toml",
           "deploy/containers", "deploy/requirements.lock", "deploy/build.lock", "deploy/constraints.txt",
           "pyproject.toml", ".dockerignore", "README.md", "LICENSE", "NOTICE")


def one(pattern, text, label):
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError("Expected one immutable " + label)
    return matches[0]


def validate(root, *, git_history=False):
    root = Path(root)
    policy = json.loads((root / POLICY).read_bytes())
    releases = policy.get("releases")
    if (policy.get("format") != "tgwitness-sealed-policy-v1" or policy.get("workflow") != WORKFLOW
            or not isinstance(releases, list) or not releases):
        raise ValueError("Invalid sealed release policy")
    pairs = []
    for release in releases:
        if not isinstance(release, dict) or set(release) != {"workflow_sha", "collector_sha"}:
            raise ValueError("Invalid sealed release pair")
        pair = tuple(release[key] for key in ("workflow_sha", "collector_sha"))
        if any(not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha) for sha in pair):
            raise ValueError("Sealed releases require full immutable commit IDs")
        pairs.append(pair)
    if len(set(pairs)) != len(pairs):
        raise ValueError("Duplicate sealed release pair")
    caller = (root / CALLER).read_text(encoding="utf-8")
    workflow_bytes = (root / COLLECTOR).read_bytes()
    workflow = workflow_bytes.decode("utf-8")
    signer = one(r"^[ \t]+uses: " + re.escape(WORKFLOW) + r"@([0-9a-f]{40})(?:[ \t]+#[^\r\n]*)?[ \t]*$", caller, "caller pin")
    collector = one(r"^\s+ref: ([0-9a-f]{40})\s*$", workflow, "collector pin")
    repository = one(r"^\s+repository: (\S+)\s*$", workflow, "collector repository")
    if repository != "phishdestroy/TgWitness" or (signer, collector) != pairs[0]:
        raise ValueError("Caller, collector and newest policy entry disagree")
    if git_history:
        def git(*args):
            result = subprocess.run(["git", *args], cwd=root, capture_output=True, check=True)
            return result.stdout
        if git("show", signer + ":" + COLLECTOR) != workflow_bytes:
            raise ValueError("Checked-out workflow differs from the pinned signer commit")
        git("merge-base", "--is-ancestor", collector, signer)
        git("merge-base", "--is-ancestor", signer, "HEAD")
        changed = set(git("diff", "--name-only", collector, "--", *RUNTIME).decode().splitlines()) - {POLICY}
        untracked = set(git("ls-files", "--others", "--exclude-standard", "--", *RUNTIME).decode().splitlines())
        if changed or untracked:
            raise ValueError("Pinned collector differs from release inputs: " + ", ".join(sorted(changed | untracked)))
    return {"workflow_sha": signer, "collector_sha": collector}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-history", action="store_true", help="Also check pinned commit bytes; needs full Git history")
    args = parser.parse_args()
    print("Sealed release pins verified:", json.dumps(validate(ROOT, git_history=args.git_history)))


if __name__ == "__main__":
    main()
