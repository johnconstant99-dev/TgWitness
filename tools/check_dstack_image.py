import hashlib
import io
import json
import struct
import sys
import tarfile
from pathlib import Path

import minicheck as pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_tdx import window  # noqa: E402
from tgwitness import cloud, dstack_image, qemu_acpi, tdx  # noqa: E402

FIXTURES = Path(__file__).parent / "tdx"
LIVE = "--live" in sys.argv
PHALA = json.loads((FIXTURES / "phala-dstack-0.5.12.json").read_text())
PHALA_COLLATERAL = json.loads((FIXTURES / "phala-dstack-0.5.12.collateral.json").read_text())

BASE = {"qemu_version": (11, 1, 0), "cpu_count": 1, "memory_size": 2 << 30, "pic": False, "smm": False,
        "hugepages": False, "numa_nodes": [], "num_gpus": 0, "num_nvswitches": 0, "num_nics": 1,
        "num_verity_volumes": 0, "extra_root_devices": [], "hotplug_off": False, "root_verity": True,
        "pci_hole64_size": None}
GOLDEN = [
    ({"qemu_version": (8, 2, 0)}, "ff0c03c7f4026a95b0b2f2e08cef7d501a3a44b4df036c9f26de91828f0215f6"),
    ({"qemu_version": (9, 1, 0)}, "ff0c03c7f4026a95b0b2f2e08cef7d501a3a44b4df036c9f26de91828f0215f6"),
    ({"qemu_version": (9, 2, 1)}, "b183eba66c6e96556f28cefe60ca92620b82488fcefaf66167aad61e2b2e73d1"),
    ({"qemu_version": (10, 0, 0)}, "d0410a8abdbba6d86a19a2eefd491376727e4e2d80c54349d7f30deca14ca6e1"),
    ({"qemu_version": (11, 0, 0)}, "e211dd453e651ef320d28c65d23f578e96468614614e7b1172f18df5052d0f1f"),
    ({}, "09f99e5dcf36b80a9258e849b3a9a70e7914244008e6a92a689eb22e4cc17a8f"),
    ({"cpu_count": 2}, "1362c6f473801b34f93df4e2966b2d3350f7f9113750da78a2cb799177157da8"),
    ({"cpu_count": 8}, "0f9fc08c5efd03f1cb3cfaa1a0a09c45dcfbc18183dbc5aa1367ad10eb65135a"),
    ({"cpu_count": 64}, "089fda95fb5d45ba9a5f46ebc99d85e1331daa4dd38f60597eec9a3d95c94bb5"),
    ({"cpu_count": 256}, "d1c3291dbdf0ccc4acdecce5f78fbe80e0ca7d6d803a62c9f5b59ee8c7e0a1b5"),
    ({"cpu_count": 4096}, "6a4bbd704addd10996632d6535432598c742789e60b29d055a7784be927588a5"),
    ({"num_nics": 0}, "93a140bbc031dc313ed4011b838c8b22ffdecb474435d9fcb294be97194c953c"),
    ({"num_nics": 2}, "fbf083121cc3b46b3b7913e45e635e6bb31e11f0cb6e029aa504bc4de68e2d64"),
    ({"num_verity_volumes": 1}, "fbf083121cc3b46b3b7913e45e635e6bb31e11f0cb6e029aa504bc4de68e2d64"),
    ({"num_verity_volumes": 4}, "7d722d7e3d811aa7978030af1d2a6c6aa68a5ab9267d7dff4e57babdf1476870"),
    ({"num_gpus": 1, "hotplug_off": True}, "0948490885eb9a777d553c7c0c529e3647533f4251b394f2f7f0a9862dadb4ca"),
    ({"num_gpus": 8, "hotplug_off": True}, "93946fc370652394d13211bd1e9361a27128a56339017f9e3645d86f0bddc1bd"),
    ({"num_gpus": 1, "num_nvswitches": 1, "hotplug_off": True},
     "bc29add92b02f264c41cfbde65beb24499cbb43e10fefe191f3a513284c050de"),
    ({"num_gpus": 1, "num_nvswitches": 4, "hotplug_off": True},
     "323e607f82db7a002bd6a71e7a6ac1ed746e94e3daba75dde2958751861c1a57"),
    *[({"cpu_count": 2, "memory_size": mib << 20, "hugepages": True, "num_gpus": 1}, digest) for mib, digest in (
        (1, "8d7620126cfd2a2edabbc8c9f289ca2993f547d595eed61fd508d24f2b52e3ac"),
        (2049, "646e5cc620fd7819f8f4756c712619d2a72c29a175fc04b79867cee80e67cf82"),
        (2815, "ee35c5e548a3f527dd12b1dd6ee14e093fd6063056470b3ef6cb6c844e4186a4"),
        (2816, "3bf181108245994ceb7e983b1fa62009dcd56f7b49fd1e96ef15eb07d04aefc9"),
        (1048576, "f22a114b0975b18200553442d6c9fab172fb930252c1a95926c594b2c25bca57"))],
    *[({"hugepages": True, "num_gpus": gpus}, "a8449287b161102ca136f892d13d6bc853d1abdc9ba7804e886f0a42784878c3")
      for gpus in (1, 8, 32)],
]


@pytest.mark.parametrize("changes, digest", GOLDEN)
def test_acpi_tables_equal_what_qemu_built(changes, digest):
    assert hashlib.sha256(qemu_acpi.build({**BASE, **changes})["tables"]).hexdigest() == digest


def test_machines_qemu_cannot_build_are_refused():
    for changes in ({"cpu_count": 0}, {"memory_size": 0}, {"cpu_count": 4097}, {"qemu_version": (7, 2, 0)},
                    {"num_gpus": 1}, {"num_nvswitches": 1, "hotplug_off": True},
                    {"numa_nodes": [{"pxb_bus": 5}, {"pxb_bus": None}], "cpu_count": 2},
                    {"numa_nodes": [{"pxb_bus": 5}, {"pxb_bus": 5}], "cpu_count": 2},
                    {"numa_nodes": [{}, {}], "cpu_count": 3}, {"extra_root_devices": ["endpoint"] * 26}):
        with pytest.raises(qemu_acpi.TopologyError):
            qemu_acpi.build({**BASE, **changes})
    for vm in ({"swtpm": True}, {"host_share_mode": "nfs"}, {"qemu_version": "8.2"}, {"extra_root_devices": ["gpu"]}):
        with pytest.raises(qemu_acpi.TopologyError):
            qemu_acpi.machine({**PHALA["vm_config"], **vm})


def phala():
    raw, log = tdx.evidence(PHALA)
    return tdx.parse_quote(raw)["report"], log, raw


def test_a_real_phala_quote_has_rtmr0_from_firmware_memory_and_qemus_acpi_tables():
    report, log, raw = phala()
    vm = PHALA["vm_config"]
    acpi = qemu_acpi.build(qemu_acpi.machine(vm))
    expected = dstack_image.rtmr0_events(PHALA["tdvf_sections"], vm["memory_size"], acpi)
    assert [bytes.fromhex(e["digest"]) for e in log if e["imr"] == 0] == expected
    assert dstack_image.fold(expected) == report["rtmr0"]
    for change in ({"cpu_count": 2}, {"memory_size": 4 << 30}, {"num_nics": 2}, {"qemu_version": "9.2.1"}):
        shape = {**vm, **change}
        acpi = qemu_acpi.build(qemu_acpi.machine(shape))
        assert dstack_image.fold(dstack_image.rtmr0_events(PHALA["tdvf_sections"], shape["memory_size"], acpi)) \
            != report["rtmr0"], change
    found = tdx.verify_quote(raw, PHALA_COLLATERAL, window(PHALA_COLLATERAL))
    assert found["status"] == "UpToDate" and found["fmspc"] == "20a06f000000"
    _, identity = tdx.measured(raw, log)
    assert identity["os_image_hash"] == PHALA["os_image_hash"]
    chain = tdx.chain_summary(raw)
    assert chain[-1]["pinned_root"] and "Intel SGX Root CA" in chain[-1]["subject"] and len(chain) == 3


def guid_table_firmware(sections, data):
    descriptor = b"TDVF" + struct.pack("<III", 16 + 32 * len(sections), 1, len(sections))
    descriptor += b"".join(struct.pack("<IIQQII", *s) for s in sections)
    tail = struct.pack("<H", 22) + dstack_image.TDX_METADATA + struct.pack("<H", 40) + dstack_image.FOOTER + bytes(32)
    size = len(data) + len(descriptor) + 4 + len(tail)
    return data + descriptor + struct.pack("<I", size - len(data)) + tail


def synthetic_image(tmp_path=None):
    code = bytes(range(256)) * 32
    firmware = guid_table_firmware([(0, 0x2000, 0xFFC00000, 0x2000, 0, 1), (0, 0, 0x809000, 0x2000, 2, 0),
                                    (0, 0, 0x800000, 0x6000, 3, 0)], code)
    kernel = bytearray(0x1400)
    struct.pack_into("<I", kernel, 0x3C, 0x80)
    kernel[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", kernel, 0x84, 0x8664, 1)
    struct.pack_into("<H", kernel, 0x84 + 16, 0xF0)
    optional = 0x84 + 20
    struct.pack_into("<H", kernel, optional, 0x20B)
    struct.pack_into("<I", kernel, optional + 60, 0x400)
    struct.pack_into("<II", kernel, optional + 0xF0 + 16, 0x1000, 0x400)
    kernel[0x202:0x206] = b"HdrS"
    struct.pack_into("<H", kernel, 0x206, 0x20C)
    struct.pack_into("<H", kernel, 0x236, 2)
    kernel[0x400:0x1400] = bytes(reversed(range(256))) * 16
    initrd = b"initrd" * 1000
    metadata = {"bios": "ovmf.fd", "kernel": "bzImage", "initrd": "initramfs.cpio.gz", "version": "0.5.12",
                "cmdline": "console=ttyS0 dstack.rootfs_hash=" + "ab" * 32, "is_dev": False, "ovmf_variant": "pre202505"}
    files = {"ovmf.fd": firmware, "bzImage": bytes(kernel), "initramfs.cpio.gz": initrd,
             "metadata.json": json.dumps(metadata).encode()}
    listing = "".join(hashlib.sha256(body).hexdigest() + "  " + name + "\n" for name, body in files.items()).encode()
    if tmp_path:
        for name, body in {**files, "sha256sum.txt": listing}.items():
            (tmp_path / name).write_bytes(body)
    return files, listing


def quote_for(image, vm):
    layout = dstack_image.sections(image["firmware"])
    rtmr0 = dstack_image.rtmr0_events(layout, vm["memory_size"], qemu_acpi.build(qemu_acpi.machine(vm)))
    meta = image["metadata"]
    report = {"mrtd": dstack_image.mrtd(image["firmware"], layout, True), "rtmr0": dstack_image.fold(rtmr0),
              "rtmr1": dstack_image.fold(dstack_image.rtmr1_events(image["kernel"], len(image["initrd"]),
                                                                   vm["memory_size"])),
              "rtmr2": dstack_image.fold(dstack_image.rtmr2_events(meta["cmdline"], image["initrd"]))}
    return report, [{"imr": 0, "digest": d.hex()} for d in rtmr0]


def test_a_synthetic_image_passes_and_every_substitution_fails(tmp_path):
    synthetic_image(tmp_path)
    image, vm = dstack_image.load(tmp_path), PHALA["vm_config"]
    report, log = quote_for(image, vm)
    status, detail, values = dstack_image.check(report, log, vm, image)
    assert status == "pass", detail
    assert values["rootfs_hash"] == "ab" * 32 and values["mrtd_order"] == "two-pass" and "1 vCPU, 2 GiB" in detail
    kernel = bytearray(image["kernel"])
    kernel[0x1300] ^= 1
    firmware = bytearray(image["firmware"])
    firmware[0x100] ^= 1
    for label, changed, vm_changes, message in (
            ("kernel", {"kernel": bytes(kernel)}, {}, "RTMR1"), ("firmware", {"firmware": bytes(firmware)}, {}, "MRTD"),
            ("initrd", {"initrd": image["initrd"] + b"x"}, {}, "RTMR1"),
            ("cmdline", {"metadata": {**image["metadata"], "cmdline": "console=ttyS0 init=/bin/sh"}}, {}, "RTMR2"),
            ("dev", {"metadata": {**image["metadata"], "is_dev": True}}, {}, "development image"),
            ("memory", {}, {"memory_size": 4 << 30}, "TD HOB"), ("cpus", {}, {"cpu_count": 2}, "ACPI tables"),
            ("nic", {}, {"num_nics": 2}, "ACPI tables")):
        status, detail, _ = dstack_image.check(report, log, {**vm, **vm_changes}, {**image, **changed})
        assert status == "fail" and message in detail, (label, detail)
    status, detail, _ = dstack_image.check(report, log, {**vm, "swtpm": True}, image)
    assert status == "unavailable" and "swtpm" in detail
    status, detail, _ = dstack_image.check(report, log, vm, {**image, "metadata": {**image["metadata"],
                                                                                    "ovmf_variant": "post202505"}})
    assert status == "unavailable" and "post202505" in detail


def test_malformed_firmware_kernel_and_folders_are_refused(tmp_path):
    files, listing = synthetic_image(tmp_path)
    firmware = files["ovmf.fd"]
    for broken in (firmware[:-1], firmware[:20], firmware.replace(b"TDVF", b"XDVF"), bytes(len(firmware))):
        with pytest.raises(dstack_image.ImageError):
            dstack_image.sections(broken)
    oversized = bytearray(firmware)
    oversized[oversized.index(b"TDVF") + 12:oversized.index(b"TDVF") + 16] = struct.pack("<I", 65)
    with pytest.raises(dstack_image.ImageError):
        dstack_image.sections(bytes(oversized))
    no_pe, headers = bytearray(files["bzImage"]), bytearray(files["bzImage"])
    no_pe[0x80:0x84] = b"XX\0\0"
    struct.pack_into("<I", headers, 0x84 + 20 + 60, 0xFFFFFF)
    for kernel, message in ((files["bzImage"][:0x800], "too short"), (bytes(no_pe), "not a PE image"),
                            (bytes(headers), "malformed")):
        with pytest.raises(dstack_image.ImageError, match=message):
            dstack_image.rtmr1_events(kernel, 10, 2 << 30)
    with pytest.raises(dstack_image.ImageError, match="memory"):
        dstack_image.patch_kernel(files["bzImage"], 10, 0x20000)
    (tmp_path / "bzImage").write_bytes(files["bzImage"] + b"x")
    with pytest.raises(dstack_image.ImageError, match="sha256sum"):
        dstack_image.load(tmp_path)
    (tmp_path / "metadata.json").write_text(json.dumps({"bios": "../ovmf.fd", "kernel": "bzImage", "initrd": "x",
                                                        "cmdline": ""}))
    with pytest.raises(dstack_image.ImageError):
        dstack_image.load(tmp_path)
    with pytest.raises(dstack_image.ImageError, match="not a dstack OS image folder"):
        dstack_image.load(tmp_path / "missing")


class Download:
    def __init__(self, body, status=200):
        self.body, self.status_code, self.urls = body, status, []

    def get(self, url, stream, timeout):
        self.urls.append(url)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_content(self, size):
        return [self.body[i:i + size] for i in range(0, len(self.body), size)]


def release(name, files, listing):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for member, body in {**files, "sha256sum.txt": listing, "rootfs.img.verity": b"r" * 100,
                             "../escape": b"x"}.items():
            info = tarfile.TarInfo(name + "/" + member)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return data.getvalue()


def test_the_published_image_is_downloaded_once_and_must_have_the_cvms_hash(tmp_path):
    files, listing = synthetic_image()
    digest = hashlib.sha256(listing).hexdigest()
    session = Download(release("dstack-0.5.12", files, listing))
    image = dstack_image.fetch("dstack-0.5.12", digest, tmp_path / "cache", session)
    assert session.urls == [dstack_image.RELEASES + "v0.5.12/dstack-0.5.12.tar.gz"] and image["digest"] == digest
    stored = sorted(p.name for p in (tmp_path / "cache" / ("dstack-0.5.12-" + digest[:16])).iterdir())
    assert stored == ["bzImage", "initramfs.cpio.gz", "metadata.json", "ovmf.fd", "sha256sum.txt"]
    assert not (tmp_path / "escape").exists()
    dstack_image.fetch("dstack-0.5.12", digest, tmp_path / "cache", session)
    assert len(session.urls) == 1
    with pytest.raises(dstack_image.ImageMismatch):
        dstack_image.fetch("dstack-0.5.12", "0" * 64, tmp_path / "other", session)
    for name, wanted in (("dstack-0.5.12/../x", digest), ("rootfs", digest), ("dstack-0.5.12", "not-a-hash")):
        with pytest.raises(dstack_image.ImageError):
            dstack_image.fetch(name, wanted, tmp_path / "cache", session)
    with pytest.raises(dstack_image.ImageError, match="HTTP 404"):
        dstack_image.fetch("dstack-0.5.13", digest, tmp_path / "cache", Download(b"", 404))


def test_the_verifier_maps_a_wrong_image_to_fail_and_a_missing_one_to_unavailable(tmp_path):
    report, log, raw = phala()
    _, identity = tdx.measured(raw, log)
    vm = PHALA["vm_config"]

    def mismatch(name, digest):
        raise dstack_image.ImageMismatch("the published " + name + " has another hash")

    def offline(name, digest):
        raise dstack_image.ImageError("network unreachable")
    assert cloud.os_image_check(report, log, vm, identity, mismatch)[0] == "fail"
    assert cloud.os_image_check(report, log, vm, identity, offline)[:2] == (
        "unavailable", "the published OS image could not be compared: network unreachable")
    folder = tmp_path / "image"
    folder.mkdir()
    synthetic_image(folder)
    with pytest.raises(dstack_image.ImageMismatch):
        cloud.image_loader(str(folder), tmp_path)("dstack-0.5.12", identity["os_image_hash"])
    assert cloud.image_loader("none", tmp_path) is None and cloud.image_loader(None, tmp_path) is None


if LIVE:
    def test_the_published_dstack_image_gives_the_real_quotes_measurements(tmp_path):
        report, log, raw = phala()
        image = dstack_image.fetch(PHALA["vm_config"]["image"], PHALA["os_image_hash"], tmp_path)
        assert {k: hashlib.sha256(image[k]).hexdigest() for k in ("firmware", "kernel", "initrd")} == PHALA["files"]
        status, detail, values = dstack_image.check(report, log, PHALA["vm_config"], image)
        assert status == "pass", detail
        print("    " + detail)


if __name__ == "__main__":
    raise SystemExit(pytest.run(globals()))
