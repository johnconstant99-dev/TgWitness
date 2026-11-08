import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path

from .verify import fingerprint, verify_bundle
from .sealed_parts import load_manifest

DEFAULT_POLICY = Path(__file__).with_name("sealed_policy.json")
REPOSITORY = "phishdestroy/TgWitness"
WORKFLOW = REPOSITORY + "/.github/workflows/sealed-collector.yml"


def verify(evidence, bundle, repo, policy=DEFAULT_POLICY, trusted_root=None, run=subprocess.run, max_gib=None,
           assembled=None, expected_selection=None, require_complete=False):
    evidence, bundle = Path(evidence).resolve(), Path(bundle).resolve()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("Expected OWNER/REPOSITORY")
    rules = json.loads(Path(policy).read_bytes())
    releases = rules.get("releases", [])
    if (rules.get("format") != "tgwitness-sealed-policy-v1" or rules.get("workflow") != WORKFLOW
            or not releases or any(not re.fullmatch(r"[0-9a-f]{40}", r.get(k, ""))
                                  for r in releases for k in ("workflow_sha", "collector_sha"))):
        raise ValueError("No approved sealed release in the trusted policy")

    approved = None
    for release in releases:
        command = ["gh", "attestation", "verify", str(evidence), "--bundle", str(bundle),
            "--repo", repo, "--signer-workflow", WORKFLOW,
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


    parts = load_manifest(evidence) if evidence.suffix == ".json" else None
    if parts:
        evidence = Path(assembled).resolve() if assembled else evidence.with_name("evidence.zip")
        from .sealed_parts import file_hash
        if evidence.stat().st_size != parts["archive_bytes"] or file_hash(evidence) != parts["archive_sha256"]:
            raise ValueError("Assembled evidence differs from the attested parts manifest")
    with zipfile.ZipFile(evidence) as candidate:
        manifest = candidate.getinfo("manifest.json")
        if manifest.file_size > 64 * 1024**2:
            raise ValueError("Manifest is too large")
        capture_format = json.loads(candidate.read(manifest)).get("format")
    if capture_format == "tgwitness-capture-v1":
        if parts or require_complete:
            raise ValueError("Official visual observations are not a complete account export")
        if max_gib is not None:
            if type(max_gib) is not int or max_gib < 1:
                raise ValueError("Invalid archive size limit")
            with zipfile.ZipFile(evidence) as incoming:
                if sum(info.file_size for info in incoming.infolist()) > max_gib * 1024**3:
                    raise ValueError("Archive exceeds the selected verification limit")
        return verify_official(evidence, approved, repo, expected_selection)
    internal = verify_bundle(evidence, max_gib=max_gib)
    if parts and internal["fingerprint"] != fingerprint(parts["public_key"]):
        raise ValueError("Multipart manifest and evidence use different signing identities")
    started, finished, accounts, selections = [], [], [], []
    with zipfile.ZipFile(evidence) as archive, archive.open("events.jsonl") as incoming:
        for line in incoming:
            event = json.loads(line)
            if event["kind"] == "sealed.started":
                started.append(event["payload"])
            elif event["kind"] == "sealed.finished":
                finished.append(event["payload"])
            elif event["kind"] == "account.authorized":
                accounts.append(event["payload"])
            elif event["kind"] == "sealed.selection":
                selections.append(event["payload"])
    if (len(started) != 1 or len(finished) != 1 or len(accounts) != 1
            or accounts[0].get("key_origin") != "created"
            or started[0].get("context", {}).get("collector_sha") != approved["collector_sha"]
            or started[0].get("context", {}).get("repository") != repo
            or started[0].get("session_import_allowed") is not False):
        raise ValueError("Archive is not the expected fresh-session sealed capture")
    if parts and (parts["context"] != started[0]["context"] or parts["recipient_sha256"] != started[0]["recipient_sha256"]):
        raise ValueError("Parts manifest context differs from the signed capture")
    from .sealed_selection import checked_selection
    expected = None
    if expected_selection is not None:
        path = Path(expected_selection)
        if path.stat().st_size > 1024**2:
            raise ValueError("Expected selection file is too large")
        expected = json.loads(path.read_bytes())
    selection = checked_selection(selections, internal, expected, require_complete)
    digest = hashlib.sha256()
    with evidence.open("rb") as incoming:
        for block in iter(lambda: incoming.read(1024**2), b""):
            digest.update(block)
    return {"verified": True, "sha256": digest.hexdigest(), "workflow": WORKFLOW, **approved,
            "journal": internal, "collection": finished[0], **selection,
            "limitation": "Acquisition is bound to the approved GitHub-hosted collector and its fresh Telegram "
                          "session. Verification trusts GitHub execution and the approved code; collection results "
                          "state the selected scope and completeness. Hardware isolation is a separate TDX check."}


def verify_official(evidence, approved, repo, expected_selection=None):
    from tgwitness_capture.verify import verify_zip
    expected = None
    if expected_selection:
        path = Path(expected_selection)
        if path.stat().st_size > 1024**2:
            raise ValueError("Expected settings file is too large")
        expected = json.loads(path.read_bytes())
    internal = verify_zip(evidence, expected_settings=expected)
    with zipfile.ZipFile(evidence) as archive, archive.open("events.jsonl") as source:
        events = [json.loads(line) for line in source]
    started = [e["payload"] for e in events if e["kind"] == "official.sealed_started"]
    finished = [e["payload"] for e in events if e["kind"] == "official.sealed_finished"]
    opened = [e["payload"] for e in events if e["kind"] == "official.opened"]
    if (len(started) != 1 or len(finished) != 1 or len(opened) != 1 or "official" not in internal
            or started[0].get("client") != "official_web" or started[0].get("session_import_allowed") is not False
            or started[0].get("network") != ("explicit-direct" if internal["official"].get("egress") == "direct"
                                             else "isolated-required-proxy")
            or started[0].get("context", {}).get("collector_sha") != approved["collector_sha"]
            or started[0].get("context", {}).get("repository") != repo
            or finished[0].get("context") != started[0]["context"]
            or finished[0].get("profile_context_closed") is not True
            or opened[0].get("login_recorded") is not False):
        raise ValueError("Archive is not an approved fresh official-client procedure")
    internal["official"]["environment_status"] = "PASS"
    internal["official"]["trust"] = "approved GitHub-hosted workflow; GitHub and official Telegram client remain trusted"
    with Path(evidence).open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    return {"verified": True, "sha256": digest, "workflow": WORKFLOW, **approved,
            "journal": internal, "collection": finished[0], "mode": "official_web",
            "selection_checked": expected is not None, "complete_account_export": False,
            "limitation": "Visual observations are bound to the approved GitHub-hosted official-client procedure. "
                          "Verification trusts GitHub and the official Telegram client; the archive records the "
                          "pages observed during the session. Account-wide export and TDX are separate modes."}


def main():
    parser = argparse.ArgumentParser(description="Verify a sealed capture against an independently trusted policy.")
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--trusted-root", type=Path)
    parser.add_argument("--assembled", type=Path, help="Assembled evidence.zip for a multipart manifest (default: beside manifest)")
    parser.add_argument("--max-gib", type=int, default=4, help="Uncompressed archive verification ceiling")
    parser.add_argument("--expected-selection", type=Path, help="Independently agreed settings JSON saved before capture")
    parser.add_argument("--require-complete", action="store_true", help="Reject partial exports and chat journals")
    parser.add_argument("--confirm-drand", action="store_true", help="Independently query public rounds in official-client recordings")
    args = parser.parse_args()
    try:
        result = verify(args.evidence, args.bundle, args.repo, args.policy, args.trusted_root,
                        max_gib=args.max_gib, assembled=args.assembled,
                        expected_selection=args.expected_selection, require_complete=args.require_complete)
        if args.confirm_drand and result.get("mode") == "official_web":
            from tgwitness_capture.beacon import confirm
            official = result["journal"]["official"]
            official["drand_verification"] = confirm(official["drand_rounds"])
            official["drand_status"] = official["drand_verification"]["status"]
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as exc:
        parser.exit(1, "Verification failed: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
