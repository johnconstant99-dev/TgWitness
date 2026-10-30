"""Host measurements for a collector deployed in high-assurance mode (python -m tgwitness.cloud).

Enabled only by TGWITNESS_ASSURANCE=<provider>; an ordinary installation never reads any of this.
The collector process measures its own host: SSH listeners and processes, current and past
logins, the boot, and what the provider's metadata service says about the server and the
cloud-init it was created with. Root on the host could falsify every value; the point is
to compare them with the records the provider and Cloudflare keep themselves.
"""
import argparse
import asyncio
import hashlib
import json
import os
import re
import struct
import urllib.request
from pathlib import Path

from .providers import NAMES, get
from .store import canonical, utcnow
from .verify import fingerprint

MODES = NAMES
DEPLOYMENT_FILE = "etc/tgwitness/assurance.json"
PREINSTALL_FILE = "etc/tgwitness/preinstall.txt"
SECRET_LINE = re.compile(r"^([ \t]*)(TGWITNESS_TOKEN|TGWITNESS_TUNNEL_TOKEN)=.*$", re.M)
# glibc struct utmp on 64-bit Linux: type, pid, line, id, user, host, exit, session, tv, addr, reserved.
UTMP = struct.Struct("<h2xi32s4s32s256shhiii16s20s")
USER_PROCESS = 7
SSH_PROCESSES = ("sshd", "sshd-session")
ATTESTATION = ("self-reported by the collector process on its own host; root on that host could "
               "falsify it. Compare with the provider's action log, firewall and the Cloudflare tunnel record.")


def mode(environ=os.environ):
    value = environ.get("TGWITNESS_ASSURANCE", "").strip().lower()
    if value and value not in MODES:
        raise RuntimeError("TGWITNESS_ASSURANCE must be one of: " + ", ".join(MODES))
    return value or None


def redact_user_data(text):
    """The cloud-init a third party may read: identical except for the two secret values."""
    return SECRET_LINE.sub(r"\1\2=REDACTED", text)


def user_data_hashes(text):
    return {"user_data_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "user_data_redacted_sha256": hashlib.sha256(redact_user_data(text).encode()).hexdigest()}


def metadata_request(url, method="GET", headers=None, timeout=2):
    # The link-local service must never be asked through a configured HTTP proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(url, method=method, headers=headers or {}), timeout=timeout) as response:
        return response.read(256 * 1024).decode()


def provider_record(selected, request=metadata_request, root=Path("/")):
    """What the provider's metadata service says about this server; read once per process start.
    The user data itself is never kept, only its hashes."""
    record = {"provider": selected}
    try:
        found = get(selected).metadata(request, Path(root))
        user_data = found.pop("user_data", None)
        record.update(found)
        if user_data is not None:
            record.update(user_data_hashes(user_data))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        record["error"] = type(exc).__name__
    return record


def text(value):
    return value.split(b"\0", 1)[0].decode(errors="replace")


def logins(path):
    """USER_PROCESS entries of a utmp/wtmp file: interactive logins, never boot or system entries."""
    data = Path(path).read_bytes()
    found = []
    for offset in range(0, len(data) - UTMP.size + 1, UTMP.size):
        kind, _pid, line, _id, user, host, _t, _e, _session, seconds, _usec, _addr, _ = \
            UTMP.unpack_from(data, offset)
        if kind == USER_PROCESS:
            found.append({"user": text(user), "line": text(line), "host": text(host), "at": seconds})
    return found


def listening(port, proc):
    """True when anything (sshd or systemd socket activation) listens on the TCP port."""
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
    """The deployment description cloud-init wrote; its hash binds it to the published cloud-init."""
    try:
        raw = (Path(root) / DEPLOYMENT_FILE).read_bytes()
        return {"sha256": hashlib.sha256(raw).hexdigest(), **json.loads(raw)}
    except (OSError, ValueError):
        return None


def snapshot(selected, provider, root=Path("/"), detail=False):
    """The measured host. With detail (the signed start record), a hand-installed server adds
    the inventory its installer took before changing anything."""
    value = {"format": "tgwitness-host-v1", "mode": selected, "measured_at": utcnow(), "provider": provider,
             "deployment": deployment(root), **host_state(root), "attestation": ATTESTATION}
    if detail and selected == "generic":
        try:
            value["preinstall"] = (Path(root) / PREINSTALL_FILE).read_bytes()[:256 * 1024].decode(errors="replace")
        except OSError:
            value["preinstall"] = None
    return value


def changes(state):
    """The part of the host state whose change is worth a signed journal record."""
    return {k: state.get(k) for k in ("boot_id", "ssh_listening", "ssh_processes", "sessions", "logins",
                                      "wtmp_sha256")}


async def assurance_loop(store, selected, provider, interval=60, root=Path("/")):
    """Append host.state whenever SSH, logins or the boot change; quiet while nothing changes."""
    last = None
    while True:
        state = await asyncio.to_thread(host_state, root)
        if changes(state) != last:
            if last is not None:
                store.append("host.state", {"mode": selected, "instance_id": provider.get("instance_id"),
                                            "before": last, **state, "attestation": ATTESTATION})
            last = changes(state)
        await asyncio.sleep(interval)


PRIVATE_HOST = ("recent_logins",)  # login sources: in the signed journal, not on the public endpoint
PRIVATE_PROVIDER = ("public_ipv4",)  # the origin address the tunnel keeps out of public view


def statement(vault, receipt, run_event_seq, selected, provider, challenge=None, root=Path("/")):
    """The public, signed answer of /api/assurance: who signs this journal and on which host."""
    host = {k: v for k, v in snapshot(selected, provider, root).items() if k not in PRIVATE_HOST}
    host["provider"] = {k: v for k, v in provider.items() if k not in PRIVATE_PROVIDER}
    value = {"format": "tgwitness-assurance-v1", "created_at": utcnow(), "challenge": challenge,
             "public_key": vault.public_key, "fingerprint": fingerprint(vault.public_key),
             "run_id": receipt["run_id"], "run_event_seq": run_event_seq, "version": receipt["version"],
             "source_tree_sha256": receipt["source_tree_sha256"], "host": host}
    return {"statement": value, "signature": vault.sign(canonical(value))}


def install_record(script, preinstall, out):
    """Run by install.sh on a hand-installed server: the hashes of the installer as it ran (with and
    without its two secrets) and of the inventory taken before installation."""
    text = Path(script).read_bytes().decode()
    hashes = user_data_hashes(text)
    value = {"format": "tgwitness-install-v1", "recorded_at": utcnow(), "sha256": hashes["user_data_sha256"],
             "redacted_sha256": hashes["user_data_redacted_sha256"],
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
    print(json.dumps(install_record(args.script, args.preinstall, args.out)))


if __name__ == "__main__":
    main()
