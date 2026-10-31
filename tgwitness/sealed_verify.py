"""Fail-closed verification against a locally trusted reusable-workflow policy."""
import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path

from .verify import verify_bundle

DEFAULT_POLICY = Path(__file__).with_name("sealed_policy.json")
REPOSITORY = "phishdestroy/TgWitness"
WORKFLOW = REPOSITORY + "/.github/workflows/sealed-collector.yml"


def verify(evidence, bundle, repo, policy=DEFAULT_POLICY, trusted_root=None, run=subprocess.run):
    evidence, bundle = Path(evidence).resolve(), Path(bundle).resolve()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("Expected OWNER/REPOSITORY")
    rules = json.loads(Path(policy).read_bytes())
    releases = rules.get("releases", [])
    if (rules.get("format") != "tgwitness-sealed-policy-v1" or rules.get("workflow") != WORKFLOW
            or not releases or any(not re.fullmatch(r"[0-9a-f]{40}", r.get(k, ""))
                                  for r in releases for k in ("workflow_sha", "collector_sha"))):
        raise ValueError("No approved sealed release in the trusted policy")
    # An envelope's workflow name or commit is never an authority to trust itself.
    approved = None
    for release in releases:
        command = ["gh", "attestation", "verify", str(evidence), "--bundle", str(bundle),
            "--repo", repo, "--signer-repo", REPOSITORY, "--signer-workflow", WORKFLOW,
            "--signer-digest", release["workflow_sha"], "--deny-self-hosted-runners", "--format", "json"]
        if trusted_root:
            command += ["--custom-trusted-root", str(Path(trusted_root).resolve())]
        result = run(command, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            checked = json.loads(result.stdout)
            if not isinstance(checked, list) or not checked:
                raise ValueError("Verifier returned no verified attestations")
            approved = release
            break
    if approved is None:
        raise ValueError("GitHub attestation did not match an approved hosted collector workflow")
    # The whole ZIP is now externally bound. Its internal signing key is authenticated
    # by that binding, so a separate user-provided fingerprint is neither needed nor trusted.
    internal = verify_bundle(evidence)
    started, finished, accounts = [], [], []
    with zipfile.ZipFile(evidence) as archive, archive.open("events.jsonl") as incoming:
        for line in incoming:
            event = json.loads(line)
            if event["kind"] == "sealed.started":
                started.append(event["payload"])
            elif event["kind"] == "sealed.finished":
                finished.append(event["payload"])
            elif event["kind"] == "account.authorized":
                accounts.append(event["payload"])
    if (len(started) != 1 or len(finished) != 1 or len(accounts) != 1
            or accounts[0].get("key_origin") != "created"
            or started[0].get("context", {}).get("collector_sha") != approved["collector_sha"]
            or started[0].get("context", {}).get("repository") != repo
            or started[0].get("session_import_allowed") is not False):
        raise ValueError("Archive is not the expected fresh-session sealed capture")
    digest = hashlib.sha256()
    with evidence.open("rb") as incoming:
        for block in iter(lambda: incoming.read(1024**2), b""):
            digest.update(block)
    return {"verified": True, "sha256": digest.hexdigest(), "workflow": WORKFLOW, **approved,
            "journal": internal, "collection": finished[0],
            "limitation": "Approved GitHub workflow provenance and byte integrity; not Telegram-signed origin, "
                          "complete historical coverage, confidential hardware, or a proof of no host access."}


def main():
    parser = argparse.ArgumentParser(description="Verify a sealed capture against an independently trusted policy.")
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--trusted-root", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.evidence, args.bundle, args.repo, args.policy, args.trusted_root)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as exc:
        parser.exit(1, "Verification failed: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
