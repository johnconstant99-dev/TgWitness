"""MRTD and RTMR0-2 of a dstack OS image, recomputed from the image Dstack-TEE publishes.

The algorithms follow dstack-mr (Dstack-TEE/dstack, Apache-2.0; see dstack_measurement.LICENSE) for OVMF's
pre-202505 layout; the ACPI tables QEMU builds for the VM's shape come from qemu_acpi.
"""

import gzip
import hashlib
import json
import re
import shutil
import struct
import tarfile
import tempfile
import uuid
from pathlib import Path

import requests

from . import qemu_acpi

RELEASES = "https://github.com/Dstack-TEE/meta-dstack/releases/download/"
NAME = re.compile(r"dstack(-nvidia)?(-dev)?-(\d{1,3}\.\d{1,3}\.\d{1,3})")
FILES = ("metadata.json", "sha256sum.txt", "digest.txt", "ovmf.fd", "bzImage", "initramfs.cpio.gz")
DOWNLOAD_LIMIT = 1024 ** 3
UNPACKED_LIMIT = 4 * 1024 ** 3
MEMBER_LIMIT = 1024 ** 3
MEMBER_COUNT_LIMIT = 256
PAGE, CHUNK = 0x1000, 0x100
MR_EXTEND, PAGE_AUG = 1, 2
TD_HOB, TEMP_MEM = 2, 3
MAX_SECTIONS, MAX_PAGES = 64, 0x10000
FOOTER = uuid.UUID("96b582de-1fb2-45f7-baea-a366c55a082d").bytes_le
TDX_METADATA = uuid.UUID("e47a6535-984a-4798-865e-4685a7bf8ec2").bytes_le
GLOBAL_VARIABLE = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
SECURITY_DATABASE = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
CFV = bytes.fromhex("344bc51c980ba621aaa00da3ed7436f7d6e549197dfe699515dfa2c6583d95e6"
                    "412af21c097d473155875ffd561d6790")
BOOT0000 = bytes.fromhex("23ada07f5261f12f34a0bd8e46760962d6b4d576a416f1fea1c64bc656b1d28e"
                         "acf7047ae6e967c58fd2a98bfa74c298")
RTMR0_EVENTS = ("TD HOB", "configuration firmware volume", "SecureBoot", "PK", "KEK", "db", "dbx", "separator",
                "ACPI table loader", "ACPI RSDP", "ACPI tables", "BootOrder", "Boot0000")
INITRD_SUFFIX = " initrd=initrd"
ACPI_DATA_SIZE = 0x28000
HIGH_MEMORY = 0xB0000000


class ImageError(ValueError):
    pass


class ImageMismatch(ImageError):
    pass


class ImageStream:
    def __init__(self, source):
        self.source, self.remaining = source, UNPACKED_LIMIT

    def read(self, size=-1):
        size = self.remaining + 1 if size < 0 else min(size, self.remaining + 1)
        data = self.source.read(size)
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ImageError("OS image archive exceeds the unpacked size limit")
        return data


def sha384(data):
    return hashlib.sha384(data).digest()


def fold(digests):
    register = bytes(48)
    for digest in digests:
        register = sha384(register + digest)
    return register


def unpack(layout, data, offset, what):
    if offset < 0 or offset + struct.calcsize(layout) > len(data):
        raise ImageError(what + " is outside the file")
    return struct.unpack_from(layout, data, offset)


def sections(firmware):
    end = len(firmware) - 32
    if end < 18 or firmware[end - 16:end] != FOOTER:
        raise ImageError("ovmf.fd has no OVMF GUID table footer")
    size = unpack("<H", firmware, end - 18, "the GUID table length")[0]
    if not 18 <= size <= end - 18:
        raise ImageError("ovmf.fd has an invalid GUID table length")
    tables, offset, entry = firmware[end - 18 - size:end - 18], size, None
    while offset > 18:
        length = unpack("<H", tables, offset - 18, "a GUID table entry")[0]
        if not 18 <= length <= offset:
            raise ImageError("ovmf.fd has an invalid GUID table entry")
        if tables[offset - 16:offset] == TDX_METADATA:
            entry = tables[offset - length:offset - 18]
            break
        offset -= length
    if entry is None or len(entry) < 4:
        raise ImageError("ovmf.fd has no TDX metadata: it is not TDVF firmware")
    start = len(firmware) - struct.unpack_from("<I", entry, len(entry) - 4)[0]
    signature, _, version, count = unpack("<4sIII", firmware, start, "the TDVF descriptor")
    if signature != b"TDVF" or version != 1 or count > MAX_SECTIONS:
        raise ImageError("ovmf.fd has an unsupported TDVF descriptor")
    found, pages = [], 0
    for index in range(count):
        data_offset, raw_size, address, size, kind, attributes = unpack(
            "<IIQQII", firmware, start + 16 + 32 * index, "TDVF section " + str(index))
        measured = size if attributes & MR_EXTEND else raw_size
        pages += size // PAGE
        if address % PAGE or size % PAGE or size < raw_size or data_offset + measured > len(firmware) \
                or address + size > 2 ** 64 or pages > MAX_PAGES:
            raise ImageError("ovmf.fd has an invalid TDVF section " + str(index))
        found.append({"offset": data_offset, "address": address, "size": size, "kind": kind,
                      "attributes": attributes})
    return found


def mrtd(firmware, layout, two_pass):
    digest = hashlib.sha384()

    def add(section, page):
        if not section["attributes"] & PAGE_AUG:
            digest.update(b"MEM.PAGE.ADD".ljust(16, b"\0") + struct.pack("<Q", section["address"] + page * PAGE)
                          + bytes(104))

    def extend(section, page):
        if section["attributes"] & MR_EXTEND:
            for chunk in range(PAGE // CHUNK):
                where = page * PAGE + chunk * CHUNK
                digest.update(b"MR.EXTEND".ljust(16, b"\0") + struct.pack("<Q", section["address"] + where) + bytes(104))
                digest.update(firmware[section["offset"] + where:section["offset"] + where + CHUNK])
    for section in layout:
        pages = range(section["size"] // PAGE)
        if two_pass:
            for page in pages:
                add(section, page)
            for page in pages:
                extend(section, page)
        else:
            for page in pages:
                add(section, page)
                extend(section, page)
    return digest.digest()


def td_hob(layout, memory):
    ranges, base = [(False, 0, memory)], 0x809000
    for section in layout:
        if section["kind"] in (TD_HOB, TEMP_MEM):
            start, end, kept = section["address"], section["address"] + section["size"], []
            for accepted, low, high in ranges:
                if accepted or high <= start or low >= end:
                    kept.append((accepted, low, high))
                    continue
                if low < start:
                    kept.append((False, low, start))
                if high > end:
                    kept.append((False, end, high))
            ranges = sorted(kept + [(True, start, end)], key=lambda r: r[1])
        if section["kind"] == TD_HOB:
            base = section["address"]
    hob = bytearray(b"\x01\x00" + struct.pack("<H", 56) + bytes(4) + struct.pack("<I", 9) + bytes(44))

    def resource(kind, start, length):
        hob.extend(b"\x03\x00" + struct.pack("<H", 48) + bytes(20) + bytes([kind]) + bytes(3)
                   + struct.pack("<IQQ", 7, start, length))
    *ranges, (_, last_start, last_end) = ranges
    for accepted, low, high in ranges:
        resource(0 if accepted else 7, low, high - low)
    if memory >= HIGH_MEMORY:
        if last_start < 0x80000000:
            resource(7, last_start, 0x80000000 - last_start)
        if last_end > 0x80000000:
            resource(7, 0x100000000, last_end - 0x80000000)
    else:
        resource(7, last_start, last_end - last_start)
    hob[48:56] = struct.pack("<Q", base + len(hob) + 8)
    return sha384(bytes(hob))


def efi_variable(vendor, name):
    return sha384(uuid.UUID(vendor).bytes_le + struct.pack("<QQ", len(name), 0) + name.encode("utf-16-le"))


def rtmr0_events(layout, memory, acpi):
    return [td_hob(layout, memory), CFV, efi_variable(GLOBAL_VARIABLE, "SecureBoot"), efi_variable(GLOBAL_VARIABLE, "PK"),
            efi_variable(GLOBAL_VARIABLE, "KEK"), efi_variable(SECURITY_DATABASE, "db"),
            efi_variable(SECURITY_DATABASE, "dbx"), sha384(bytes(4)), sha384(acpi["loader"]), sha384(acpi["rsdp"]),
            sha384(acpi["tables"]), sha384(bytes(2)), BOOT0000]


def patch_kernel(kernel, initrd_size, memory):
    if len(kernel) < 0x1000:
        raise ImageError("the kernel image is too short")
    data = bytearray(kernel)
    protocol = struct.unpack_from("<H", data, 0x206)[0]
    real, command_line = (0x90000, 0x9a000) if protocol < 0x200 or not data[0x211] & 1 else (0x10000, 0x20000)
    if protocol >= 0x200:
        data[0x210] = 0xb0
    if protocol >= 0x201:
        data[0x211] |= 0x80
        data[0x224:0x228] = struct.pack("<I", max(command_line - real - 0x200, 0))
    if protocol >= 0x202:
        data[0x228:0x22c] = struct.pack("<I", command_line)
    else:
        data[0x20:0x24] = struct.pack("<HH", 0xa33f, command_line - real)
    if initrd_size:
        if protocol < 0x200:
            raise ImageError("the kernel image is too old for an initrd")
        if protocol >= 0x20c:
            limit = 0xffffffff if struct.unpack_from("<H", data, 0x236)[0] & 2 else 0x37ffffff
        elif protocol >= 0x203:
            limit = struct.unpack_from("<I", data, 0x22c)[0] or 0x37ffffff
        else:
            limit = 0x37ffffff
        low = HIGH_MEMORY if memory < HIGH_MEMORY else 0x80000000
        available = min(memory, low) - ACPI_DATA_SIZE
        if available <= 0:
            raise ImageError("the VM's memory is smaller than QEMU's ACPI data")
        limit = min(limit, available - 1)
        if initrd_size >= limit:
            raise ImageError("the initrd does not fit below the kernel's limit")
        data[0x218:0x220] = struct.pack("<II", (limit - initrd_size) & ~4095, initrd_size)
    return bytes(data)


def authenticode(image):
    pe = unpack("<I", image, 0x3c, "the DOS header")[0]
    if unpack("<I", image, pe, "the PE signature")[0] != 0x4550:
        raise ImageError("the kernel is not a PE image")
    coff = pe + 4
    count, = unpack("<H", image, coff + 2, "the COFF header")
    optional_size, = unpack("<H", image, coff + 16, "the COFF header")
    optional = coff + 20
    plus = unpack("<H", image, optional, "the optional header")[0] == 0x20b
    checksum, certificates = optional + 64, optional + (112 if plus else 96) + 4 * 8
    headers, = unpack("<I", image, optional + 60, "the optional header")
    if not certificates + 8 <= headers <= len(image):
        raise ImageError("the kernel's PE headers are malformed")
    digest = hashlib.sha384(image[:checksum] + image[checksum + 4:certificates] + image[certificates + 8:headers])
    hashed, parts = headers, []
    for index in range(count):
        size, pointer = unpack("<II", image, optional + optional_size + 40 * index + 16, "a PE section header")
        if size:
            parts.append((pointer, size))
    for pointer, size in sorted(parts):
        digest.update(image[pointer:pointer + size])
        hashed += size
    table, table_size = unpack("<II", image, certificates, "the certificate directory")
    if table and table_size and len(image) - hashed > table_size:
        digest.update(image[hashed:len(image) - table_size])
    if len(image) % 8:
        digest.update(bytes(8 - len(image) % 8))
    return digest.digest()


def rtmr1_events(kernel, initrd_size, memory, normalized=False):
    measured = kernel if normalized else patch_kernel(kernel, initrd_size, memory)
    return [authenticode(measured), sha384(b"Calling EFI Application from Boot Option"), sha384(bytes(4)),
            sha384(b"Exit Boot Services Invocation"), sha384(b"Exit Boot Services Returned with Success")]


def rtmr2_events(command_line, initrd):
    return [sha384((command_line + INITRD_SUFFIX).encode("utf-16-le") + b"\0\0"), sha384(initrd)]


def load(folder):
    folder = Path(folder)
    try:
        listing = (folder / "sha256sum.txt").read_bytes()
        lines = listing.decode().splitlines()
        metadata = json.loads((folder / "metadata.json").read_bytes())
    except (OSError, ValueError) as exc:
        raise ImageError("not a dstack OS image folder: " + str(folder) + " (" + type(exc).__name__ + ")") from None
    if not isinstance(metadata, dict) or not isinstance(metadata.get("cmdline"), str):
        raise ImageError("metadata.json has no kernel command line")
    listed = {}
    for line in lines:
        digest, _, name = line.strip().partition("  ")
        listed[name.strip()] = digest.lower()
    files = {}
    for role, name in (("firmware", metadata.get("bios")), ("kernel", metadata.get("kernel")),
                       ("initrd", metadata.get("initrd")), ("metadata.json", "metadata.json")):
        if not isinstance(name, str) or "/" in name or "\\" in name or name not in listed:
            raise ImageError("sha256sum.txt does not list the image's " + role)
        try:
            data = (folder / name).read_bytes()
        except OSError:
            raise ImageError("the image folder has no " + name) from None
        if hashlib.sha256(data).hexdigest() != listed[name]:
            raise ImageError(name + " does not match sha256sum.txt")
        files[role] = data
    files.pop("metadata.json")
    return {"folder": folder, "digest": hashlib.sha256(listing).hexdigest(), "metadata": metadata,
            "version": metadata.get("version"), **files}


def fetch(name, digest, cache, session=None):
    match = NAME.fullmatch(name or "")
    if not match or not re.fullmatch(r"[0-9a-f]{64}", digest or ""):
        raise ImageError("unexpected OS image name or hash: " + repr(name))
    cache = Path(cache)
    folder = cache / (name + "-" + digest[:16])
    if folder.is_dir():
        image = load(folder)
        if image["digest"] == digest:
            return image
    url = RELEASES + "v" + match.group(3) + "/" + name + ".tar.gz"
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=cache) as work:
        archive, staging = Path(work) / "image.tar.gz", Path(work) / name
        try:
            with (session or requests).get(url, stream=True, timeout=60) as response:
                if response.status_code != 200:
                    raise ImageError(url + " answered HTTP " + str(response.status_code))
                received = 0
                with archive.open("wb") as out:
                    for chunk in response.iter_content(1 << 20):
                        received += len(chunk)
                        if received > DOWNLOAD_LIMIT:
                            raise ImageError(url + " is larger than expected")
                        out.write(chunk)
        except requests.RequestException as exc:
            raise ImageError(url + ": " + type(exc).__name__) from None
        staging.mkdir()
        try:
            with gzip.open(archive, "rb") as compressed, tarfile.open(fileobj=ImageStream(compressed), mode="r|") as bundle:
                seen = set()
                for count, member in enumerate(bundle, 1):
                    if count > MEMBER_COUNT_LIMIT:
                        raise ImageError("OS image archive has too many members")
                    parts = member.name.split("/")
                    if len(parts) != 2 or parts[0] != name or parts[1] not in FILES:
                        continue
                    if not member.isfile() or member.issparse():
                        raise ImageError("OS image member must be a regular file: " + parts[1])
                    if parts[1] in seen:
                        raise ImageError("OS image archive repeats " + parts[1])
                    seen.add(parts[1])
                    limit = 1 << 20 if parts[1] in ("metadata.json", "sha256sum.txt", "digest.txt") else MEMBER_LIMIT
                    if member.size < 0 or member.size > limit:
                        raise ImageError("OS image member exceeds the size limit: " + parts[1])
                    with bundle.extractfile(member) as source, (staging / parts[1]).open("xb") as target:
                        shutil.copyfileobj(source, target, length=1 << 20)
        except (tarfile.TarError, EOFError, gzip.BadGzipFile) as exc:
            raise ImageError("invalid OS image archive: " + type(exc).__name__) from None
        image = load(staging)
        if image["digest"] != digest:
            raise ImageMismatch("the published " + name + " has OS image hash " + image["digest"] + ", not the CVM's "
                                + digest)
        if folder.exists():
            shutil.rmtree(folder)
        staging.replace(folder)
    return load(folder)


def check(report, event_log, vm, image):
    """Compare a quote's MRTD and RTMR0-2 with the image. Returns status, detail and the values compared."""
    meta, memory = image["metadata"], vm.get("memory_size")
    name = "dstack" + ("-dev" if meta.get("is_dev") else "") + "-" + str(meta.get("version"))
    if meta.get("ovmf_variant", "pre202505") != "pre202505":
        return "unavailable", "OVMF variant " + str(meta.get("ovmf_variant")) + " of " + name + " is not modelled", {}
    if not isinstance(memory, int) or memory <= 0:
        return "unavailable", "the VM configuration gives no memory size", {}
    try:
        shape = qemu_acpi.machine(vm)
        acpi = qemu_acpi.build(shape)
    except (ValueError, TypeError) as exc:
        return "unavailable", "the VM's shape is not modelled: " + str(exc), {}
    layout = sections(image["firmware"])
    candidates = {"two-pass": mrtd(image["firmware"], layout, True), "single-pass": mrtd(image["firmware"], layout, False)}
    expected0 = rtmr0_events(layout, memory, acpi)
    rtmr0 = fold(expected0)
    rtmr1 = fold(rtmr1_events(image["kernel"], len(image["initrd"]), memory, meta.get("kernel_header_normalized")))
    rtmr2 = fold(rtmr2_events(meta["cmdline"], image["initrd"]))
    problems = []
    order = next((k for k, v in candidates.items() if v == report["mrtd"]), None)
    if order is None:
        problems.append("MRTD is not the firmware's")
    if rtmr0 != report["rtmr0"]:
        try:
            logged = [bytes.fromhex(e.get("digest") or "") for e in event_log if e.get("imr") == 0]
        except (TypeError, ValueError):
            logged = []
        differ = [RTMR0_EVENTS[i] for i, want in enumerate(expected0) if i >= len(logged) or logged[i] != want]
        problems.append("RTMR0 is not the firmware's, the memory's and the VM shape's ACPI tables"
                        + ("; the event log differs at " + ", ".join(differ) if logged and differ else ""))
    if rtmr1 != report["rtmr1"]:
        problems.append("RTMR1 is not the kernel's")
    if rtmr2 != report["rtmr2"]:
        problems.append("RTMR2 is not the command line and initrd's")
    if meta.get("is_dev"):
        problems.append(name + " is a development image: SSH and debugging are possible")
    rootfs = re.search(r"dstack\.rootfs_hash=([0-9a-f]{64})", meta["cmdline"])
    machine = ("QEMU " + ".".join(map(str, shape["qemu_version"])) + ", " + str(shape["cpu_count"]) + " vCPU, "
               + (str(memory >> 30) + " GiB" if memory % (1 << 30) == 0 else str(memory) + " bytes"))
    values = {"image": name, "os_image_hash": image["digest"], "mrtd": report["mrtd"].hex(), "mrtd_order": order,
              "rtmr0": rtmr0.hex(), "rtmr1": rtmr1.hex(), "rtmr2": rtmr2.hex(), "machine": machine,
              "rootfs_hash": rootfs.group(1) if rootfs else None, "cmdline": meta["cmdline"] + INITRD_SUFFIX,
              "acpi": {k: sha384(acpi[k]).hex() for k in ("loader", "rsdp", "tables")},
              "rtmr0_events": dict(zip(RTMR0_EVENTS, (e.hex() for e in expected0)))}
    if problems:
        return "fail", "; ".join(problems) + " (compared with the published " + name + ", " + machine + ")", values
    return "pass", ("MRTD and RTMR0-2 equal the values computed from the published " + name + " for " + machine
                    + ": its firmware, kernel, initrd and command line with root file system hash "
                    + (values["rootfs_hash"] or "none")[:16] + "..., and the ACPI tables QEMU builds for this VM"), values
