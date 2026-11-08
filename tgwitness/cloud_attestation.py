import hashlib
import json
import tarfile
from pathlib import Path

import requests

from . import dstack_image, tdx

TDX_OK = ("UpToDate",)


def hex_id(value):
    return str(value or "").lower().removeprefix("0x")


def intel_collateral(path=None, session=None):
    if path:
        fixed = json.loads(Path(path).read_text(encoding="utf-8"))
        return lambda raw: fixed
    memo = {}

    def collateral(raw):
        fmspc = tdx.pck_extension(tdx.pem_chain(tdx.parse_quote(raw)["pck_chain"])[0])["fmspc"]
        if fmspc not in memo:
            memo[fmspc] = tdx.fetch_collateral(raw, session or requests.Session())
        return memo[fmspc]
    return collateral


def intel_check(raw, collateral, now=None):
    try:
        found = tdx.verify_quote(raw, collateral(raw), now)
    except tdx.QuoteError as exc:
        return "fail", str(exc), None
    except (requests.RequestException, OSError, ValueError, KeyError) as exc:
        return "unavailable", "Intel's collateral could not be read (" + type(exc).__name__ + "); pass " \
               "--tdx-collateral with collateral fetched from Intel's PCS", None
    advisories = (" with " + ", ".join(found["advisory_ids"][:12])) if found["advisory_ids"] else ""
    return ("pass" if found["status"] in TDX_OK else "review"), (
        "Intel TCB status " + found["status"] + advisories + "; quote v" + str(found["quote_version"]) + ", FMSPC "
        + found["fmspc"] + ", TCB level of " + found["tcb_date"] + ", Intel collateral issued "
        + found["collateral_issued"] + "; not in debug mode, not migratable"), found


def image_loader(option, folder, session=None):
    """The published dstack OS images, kept in folder/dstack-images ("auto"), in a given folder, or none."""
    if option in (None, "none"):
        return None
    cache = Path(folder) / "dstack-images" if option == "auto" else Path(option)

    def load(name, digest):
        if (cache / "metadata.json").is_file():
            image = dstack_image.load(cache)
            if image["digest"] != digest:
                raise dstack_image.ImageMismatch(str(cache) + " has OS image hash " + image["digest"] + ", not the "
                                                 "CVM's " + str(digest))
            return image
        return dstack_image.fetch(name, digest, cache, session)
    return load


def os_image_check(report, event_log, vm, identity, image):
    digest = hex_id(identity["os_image_hash"] or vm.get("os_image_hash"))
    try:
        found = image(vm.get("image"), digest)
    except dstack_image.ImageMismatch as exc:
        return "fail", str(exc), {}
    except (dstack_image.ImageError, OSError, tarfile.TarError) as exc:
        return "unavailable", "the published OS image could not be compared: " + str(exc), {}
    return dstack_image.check(report, event_log, vm, found)


def attestation_checks(answer, record, reference=None, published=None, collateral=None, expected=None, now=None,
                       image=None, details=None, *, compose):
    statement = answer["statement"]
    seen = (statement.get("host") or {}).get("provider") or {}
    evidence = answer.get("tdx") or {}
    title = "The collector answers with an Intel TDX quote whose RTMR3 replays from its event log"
    if evidence.get("error") or not evidence.get("quote"):
        return [("tdx_quote", "fail", title, evidence.get("error") or "the answer carries no quote")]
    try:
        raw, log = tdx.evidence(evidence)
        quote, identity = tdx.measured(raw, log)
    except (tdx.QuoteError, ValueError, KeyError, TypeError) as exc:
        return [("tdx_quote", "fail", title, type(exc).__name__ + ": " + str(exc))]
    checks = []
    bound = quote["report"]["report_data"] == tdx.report_data(statement)
    checks.append(("tdx_binding", "pass" if bound else "fail", "The quote covers this signed statement and its challenge",
                   "report data is SHA-512 of the statement" if bound else
                   "the quote's report data is not SHA-512 of this statement: it vouches for something else"))
    status, detail, intel = intel_check(raw, collateral or intel_collateral(), now)
    checks.append(("tdx_quote", status, "Intel vouches for the quote: a genuine TDX platform at a current TCB level",
                   detail))
    text = seen.get("app_compose")
    same = isinstance(text, str) and hashlib.sha256(text.encode()).hexdigest() == identity["compose_hash"]
    after = identity["after_ready"]
    checks.append(("tdx_compose_hash", "fail" if not same else "review" if after else "pass",
                   "RTMR3 measures the app-compose the collector reports",
                   ("compose hash " + identity["compose_hash"] if same else "the reported app-compose is not the one "
                    "RTMR3 measured (" + identity["compose_hash"] + ")")
                   + ("; extended after boot: " + ", ".join(after[:10]) if after else "")))
    status, detail = compose(text, reference, published) if same else \
        ("fail", "not compared: the reported app-compose is not the measured one")
    checks.append(("tdx_compose", status, "The measured compose is the deployed commit's and runs nothing else", detail))
    server, problems, notes = record.get("server") or {}, [], []
    if hex_id(identity["app_id"]) != hex_id(server.get("app_id")):
        problems.append("app ID " + identity["app_id"] + " is not the deployed " + str(server.get("app_id")))
    if identity["instance_id"] is None:
        problems.append("no instance-id event")
    elif hex_id(identity["instance_id"]) != hex_id(seen.get("instance_id")) or (
            server.get("instance_id") and hex_id(identity["instance_id"]) != hex_id(server["instance_id"])):
        problems.append("instance " + identity["instance_id"] + " is not the deployed or reported instance")
    provider = identity["key_provider"]
    name = provider.get("name") if isinstance(provider, dict) else provider
    if name != "kms":
        (notes if str(name).startswith("local") else problems).append("key provider " + json.dumps(provider)[:120])
    if identity["storage_encrypted"] == "0":
        problems.append("the data disk is not encrypted")
    checks.append(("tdx_identity", "fail" if problems else "review" if notes else "pass",
                   "The quote comes from the deployed CVM, with KMS keys and an encrypted disk",
                   "; ".join(problems + notes) or "app " + identity["app_id"] + ", instance " + identity["instance_id"]
                   + ", key provider kms" + (", disk encrypted" if identity["storage_encrypted"] == "1" else "")))
    report = {k: v.hex() for k, v in quote["report"].items()}
    try:
        vm = json.loads(evidence.get("vm_config") or "{}")
    except ValueError:
        vm = {}
    vm = vm if isinstance(vm, dict) else {}
    os_image = {}
    if expected or not image:
        status, detail = tdx.compare_measurements(report, expected)
    else:
        status, detail, os_image = os_image_check(quote["report"], log, vm, identity, image)
    images = {hex_id(h) for h in (vm.get("os_image_hash"), identity["os_image_hash"], server.get("os_image_hash")) if h}
    if len(images) > 1:
        status, detail = "fail", "the OS image hashes disagree: " + ", ".join(sorted(images)) + "; " + detail
    checks.append(("tdx_os", status, "Firmware, kernel and command line are the dstack OS image's",
                   detail + ("; OS image " + next(iter(images)) if len(images) == 1 else "")
                   + (", " + str(vm.get("cpu_count")) + " vCPU, " + str(vm.get("memory_size")) + " bytes" if vm else "")))
    if details is not None:
        try:
            certificates = tdx.chain_summary(raw)
        except tdx.QuoteError:
            certificates = []
        details.update({"certificates": certificates, "quote": {"version": quote.get("version"), "tee": "Intel TDX",
                                  **{k: report[k] for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "report_data",
                                                            "td_attributes", "xfam") if k in report}},
                        "intel": intel, "identity": {k: identity.get(k) for k in (
                            "app_id", "compose_hash", "instance_id", "os_image_hash", "key_provider")},
                        "vm": vm, "os_image": os_image})
    return checks
