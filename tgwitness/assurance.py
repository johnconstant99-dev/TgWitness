import argparse
import asyncio
import hashlib
import json
import os
import re
import struct
import threading
import time
import urllib.request
from pathlib import Path

from .providers import NAMES, get
from .store import canonical, utcnow
from .tdx import report_data
from .verify import fingerprint

MODES = NAMES
BEACON_SERVER = "https://ntfy.sh/"
BEACON = re.compile(re.escape(BEACON_SERVER) + r"tgw-[0-9a-f]{32}")
QUICK_HOST = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com")
ADDRESS_SIGNED = "tgwitness-address-v2"
TUNNEL_METRICS = "http://127.0.0.1:20241/quicktunnel"
DEPLOYMENT_FILE = "etc/tgwitness/assurance.json"
PREINSTALL_FILE = "etc/tgwitness/preinstall.txt"
SECRET_LINE = re.compile(r"^([ \t]*)(TGWITNESS_TOKEN|TGWITNESS_TUNNEL_TOKEN)=.*$", re.M)

UTMP = struct.Struct("<h2xi32s4s32s256shhiii16s20s")
USER_PROCESS = 7
SSH_PROCESSES = ("sshd", "sshd-session")
ATTESTATION = ("self-reported by the collector process on its own host; root on that host could "
               "falsify it. Compare with the provider's action log, firewall and the Cloudflare tunnel record.")
QUOTES = threading.Lock()
CACHE = {}


def mode(environ=os.environ):
    value = environ.get("TGWITNESS_ASSURANCE", "").strip().lower()
    if value and value not in MODES:
        raise RuntimeError("TGWITNESS_ASSURANCE must be one of: " + ", ".join(MODES))
    return value or None


def redact_user_data(text):
    return SECRET_LINE.sub(r"\1\2=REDACTED", text)


def user_data_hashes(text):
    return {"user_data_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "user_data_redacted_sha256": hashlib.sha256(redact_user_data(text).encode()).hexdigest()}


def metadata_request(url, method="GET", headers=None, timeout=2):

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(url, method=method, headers=headers or {}), timeout=timeout) as response:
        return response.read(256 * 1024).decode()


def provider_record(selected, request=metadata_request, root=Path("/")):
    record = {"provider": selected}
    try:
        found = get(selected).metadata(request, Path(root))
        user_data = found.pop("user_data", None)
        record.update(found)
        if user_data is not None:
            record.update(user_data_hashes(user_data), user_data_redacted=redact_user_data(user_data))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        record["error"] = type(exc).__name__
    return record


def text(value):
    return value.split(b"\0", 1)[0].decode(errors="replace")


def logins(path):
    data = Path(path).read_bytes()
    found = []
    for offset in range(0, len(data) - UTMP.size + 1, UTMP.size):
        kind, _pid, line, _id, user, host, _t, _e, _session, seconds, _usec, _addr, _ = \
            UTMP.unpack_from(data, offset)
        if kind == USER_PROCESS:
            found.append({"user": text(user), "line": text(line), "host": text(host), "at": seconds})
    return found


def listening(port, proc):
    for name in ("net/tcp", "net/tcp6"):
        try:
            rows = (Path(proc) / name).read_text().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            if len(fields) > 3 and fields[3] == "0A" and int(fields[1].rsplit(":", 1)[1], 16) == port:
                return True
    return False


def processes(names, proc):
    count = 0
    for entry in Path(proc).iterdir() if Path(proc).is_dir() else ():
        if entry.name.isdigit():
            try:
                count += (entry / "comm").read_text().strip() in names
            except OSError:
                pass
    return count


def host_state(root=Path("/")):
    root = Path(root)
    state = {}
    try:
        state["boot_id"] = (root / "proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        state["boot_id"] = None
    state["ssh_listening"] = listening(22, root / "proc")
    state["ssh_processes"] = processes(SSH_PROCESSES, root / "proc")
    for key, name in (("sessions", "run/utmp"), ("logins", "var/log/wtmp")):
        try:
            found = logins(root / name)
            state[key] = len(found)
            if key == "logins":
                state["recent_logins"] = found[-10:]
                state["wtmp_sha256"] = hashlib.sha256((root / name).read_bytes()).hexdigest()
        except OSError:
            state[key] = None
    return state


def deployment(root=Path("/")):
    try:
        raw = (Path(root) / DEPLOYMENT_FILE).read_bytes()
        return {"sha256": hashlib.sha256(raw).hexdigest(), **json.loads(raw)}
    except (OSError, ValueError):
        return None


def snapshot(selected, provider, root=Path("/"), detail=False):
    value = {"format": "tgwitness-host-v1", "mode": selected, "measured_at": utcnow(),
             "provider": {k: v for k, v in provider.items() if k != "user_data_redacted"},
             "deployment": deployment(root), **host_state(root), "attestation": ATTESTATION}
    if detail and selected == "generic":
        try:
            value["preinstall"] = (Path(root) / PREINSTALL_FILE).read_bytes()[:256 * 1024].decode(errors="replace")
        except OSError:
            value["preinstall"] = None
    return value


def changes(state):
    return {k: state.get(k) for k in ("boot_id", "ssh_listening", "ssh_processes", "sessions", "logins",
                                      "wtmp_sha256")}


async def assurance_loop(store, selected, provider, interval=60, root=Path("/"), status=None):
    last = None
    while True:
        state = await asyncio.to_thread(host_state, root)
        if status is not None:
            status.update(state=state, measured_at=utcnow())
        if changes(state) != last:
            if last is not None:
                store.append("host.state", {"mode": selected, "instance_id": provider.get("instance_id"),
                                            "before": last, **state, "attestation": ATTESTATION})
            last = changes(state)
        await asyncio.sleep(interval)


def address_post(vault, host, now):
    text = ADDRESS_SIGNED + " " + host + " " + str(now)
    return text + " " + vault.sign(text.encode())


def quick_tunnel_host(url=TUNNEL_METRICS):
    answer = json.loads(metadata_request(url, timeout=5))
    host = answer.get("hostname") if isinstance(answer, dict) else None
    return host if isinstance(host, str) and QUICK_HOST.fullmatch(host) else None


def post_address(topic, body):
    urllib.request.urlopen(urllib.request.Request(topic, body.encode(), method="POST"), timeout=20).close()


async def address_loop(vault, topic, interval=30, every=10800, host=quick_tunnel_host, post=post_address):
    if not BEACON.fullmatch(topic or ""):
        return
    last, sent = None, 0
    while True:
        try:
            found = await asyncio.to_thread(host)
            now = int(time.time())
            if found and (found != last or now - sent >= every):
                await asyncio.to_thread(post, topic, address_post(vault, found, now))
                last, sent = found, now
        except (OSError, ValueError):
            pass
        await asyncio.sleep(interval)


PRIVATE_HOST = ("recent_logins",)
PRIVATE_PROVIDER = ("public_ipv4",)


def attestation(selected, value):
    attest = getattr(get(selected), "attest", None)
    if attest is None:
        return None
    try:
        with QUOTES:
            return attest(report_data(value))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {"error": type(exc).__name__ + ": " + str(exc)[:200]}


def start_attestation(selected, receipt):
    return attestation(selected, start_binding(receipt))


def start_binding(run):
    value = {"format": "tgwitness-tdx-start-v1", "public_key": run.get("public_key"), "run_id": run.get("run_id"),
             "source_tree_sha256": run.get("source_tree_sha256"), "host": run.get("host")}
    if "source_policy" in run:
        value["source_policy"] = run["source_policy"]
    return value


def statement(vault, receipt, run_event_seq, selected, provider, challenge=None, root=Path("/")):
    if not challenge and CACHE.get("until", 0) > time.monotonic() and CACHE.get("key") == vault.public_key:
        return CACHE["answer"]
    host = {k: v for k, v in snapshot(selected, provider, root).items() if k not in PRIVATE_HOST}
    host["provider"] = {k: v for k, v in provider.items() if k not in PRIVATE_PROVIDER}
    value = {"format": "tgwitness-assurance-v1", "created_at": utcnow(), "challenge": challenge,
             "public_key": vault.public_key, "fingerprint": fingerprint(vault.public_key),
             "run_id": receipt["run_id"], "run_event_seq": run_event_seq, "version": receipt["version"],
             "source_tree_sha256": receipt["source_tree_sha256"], "host": host}
    if "source_policy" in receipt:
        value["source_policy"] = receipt["source_policy"]
    answer = {"statement": value, "signature": vault.sign(canonical(value))}
    quote = attestation(selected, value)
    if quote is not None:
        answer["tdx"] = quote
        if not challenge:
            CACHE.update(until=time.monotonic() + 30, key=vault.public_key, answer=answer)
    return answer


def install_record(script, preinstall, out):
    text = Path(script).read_bytes().decode()
    hashes = user_data_hashes(text)
    value = {"format": "tgwitness-install-v1", "recorded_at": utcnow(), "sha256": hashes["user_data_sha256"],
             "redacted_sha256": hashes["user_data_redacted_sha256"], "redacted": redact_user_data(text),
             "preinstall_sha256": hashlib.sha256(Path(preinstall).read_bytes()).hexdigest()}
    Path(out).write_text(json.dumps(value, sort_keys=True) + "\n")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m tgwitness.assurance",
                                     description="Record a hand-installed server's installer for self-attested mode")
    parser.add_argument("command", choices=["install-record"])
    parser.add_argument("script", type=Path)
    parser.add_argument("preinstall", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args(argv)
    print(json.dumps({k: v for k, v in install_record(args.script, args.preinstall, args.out).items() if k != "redacted"}))


if __name__ == "__main__":
    main()
