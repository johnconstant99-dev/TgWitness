
import struct
import uuid

TABLE_BLOB_SIZE = 128 * 1024
LOADER_BLOB_SIZE = 4096
V8, V9_PRE_92, V9_2, V10, V11_0, V11_1 = range(6)
LEGACY_PXB_BUS, FIRST_PXB_SLOT, LPC_SLOT = 5, 0x10, 0x1F
ENDPOINT, ROOT_PORT = "endpoint", "root_port"
SYSTEM_IO, PCI_CONFIG = 1, 2
BYTE_ACCESS, DWORD_ACCESS = 1, 3
PRESERVE, WRITE_AS_ZEROES = 0, 2
NOT_CACHEABLE, CACHEABLE = 0, 1
MEMORY, IO_RANGE, BUS_NUMBER = 0, 1, 2


class TopologyError(ValueError):
    pass


def compatibility(version):
    major, minor = version[0], version[1]
    if major == 8:
        return V8
    if major == 9:
        return V9_PRE_92 if minor <= 1 else V9_2
    if major == 10:
        return V10
    if major == 11:
        return V11_0 if minor == 0 else V11_1
    if major >= 12:
        return V11_1
    raise TopologyError("QEMU " + ".".join(map(str, version)) + " is older than the ACPI layouts modelled")


def u16(value):
    return struct.pack("<H", value & 0xFFFF)


def u32(value):
    return struct.pack("<I", value & 0xFFFFFFFF)


def u64(value):
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def num(value):
    if value == 0:
        return b"\x00"
    if value == 1:
        return b"\x01"
    if value <= 0xFF:
        return b"\x0a" + bytes([value])
    if value <= 0xFFFF:
        return b"\x0b" + u16(value)
    if value <= 0xFFFFFFFF:
        return b"\x0c" + u32(value)
    return b"\x0e" + u64(value)


def pkg_length(length, include_self=True):
    width = 1 if length < 63 else 2 if length < 4094 else 3 if length < 1048573 else 4
    value = length + (width if include_self else 0)
    if width == 1:
        return bytes([value & 0xFF])
    return bytes([((width - 1) << 6) | (value & 0x0F)]) + bytes((value >> (4 + 8 * i)) & 0xFF for i in range(width - 1))


def path(name):
    root = name.startswith("\\")
    parts = name[root:].split(".")
    if any(len(part) != 4 for part in parts):
        raise ValueError("AML name segments are four characters: " + name)
    prefix = b"\\" if root else b""
    if len(parts) == 2:
        prefix += b"\x2e"
    elif len(parts) > 2:
        prefix += b"\x2f" + bytes([len(parts)])
    return prefix + "".join(parts).encode()


def string(text):
    return b"\x0d" + text.encode() + b"\x00"


def eisa(name):
    value = ((ord(name[0]) - 0x40) << 26) | ((ord(name[1]) - 0x40) << 21) | ((ord(name[2]) - 0x40) << 16) \
        | int(name[3:], 16)
    return num(int.from_bytes(value.to_bytes(4, "big"), "little"))


def name(target, value):
    return b"\x08" + path(target) + value


def block(opcode, body):
    return opcode + pkg_length(len(body)) + body


def package(*children):
    return block(b"\x12", bytes([len(children)]) + b"".join(children))


def fixed_package(count):
    return b"\x12" + pkg_length(1) + bytes([count])


def buffer(data):
    return block(b"\x11", num(len(data)) + data)


def to_uuid(text):
    return buffer(uuid.UUID(text).bytes_le)


def resources(*descriptors):
    data = b"".join(descriptors) + b"\x79\x00"
    return block(b"\x11", num(len(data)) + data)


def address_space(width, kind, flags, low, high, translation=0):
    size, pack = {2: (2, u16), 4: (4, u32), 8: (8, u64)}[width]
    descriptor = {2: 0x88, 4: 0x87, 8: 0x8A}[width]
    mask = (1 << (8 * size)) - 1
    return bytes([descriptor]) + u16(3 + 5 * size) + bytes([kind, 0x0C, flags]) + pack(0) + pack(low) + pack(high) \
        + pack(translation) + pack((high - low + 1) & mask)


def memory_range(width, cacheable, low, high):
    return address_space(width, MEMORY, (cacheable << 1) | 1, low, high)


def io(low, high, alignment, length):
    return b"\x47\x01" + u16(low) + u16(high) + bytes([alignment, length])


def interrupts(numbers, edge, consumer=True, active_low=False, shared=True):
    flags = (shared << 3) | (active_low << 2) | (edge << 1) | consumer
    return b"\x89" + u16(2 + 4 * len(numbers)) + bytes([flags, len(numbers)]) + b"".join(u32(n) for n in numbers)


def irq(number, flags=None):
    mask = u16(1 << number)
    return b"\x22" + mask if flags is None else b"\x23" + mask + bytes([flags])


def device(target, *children):
    return block(b"\x5b\x82", path(target) + b"".join(children))


def scope(target, *children):
    return block(b"\x10", path(target) + b"".join(children))


def root_scope(*children):
    return block(b"\x10", b"\\\x00" + b"".join(children))


def method(target, args, serialized, *children):
    return block(b"\x14", path(target) + bytes([(args & 7) | (serialized << 3)]) + b"".join(children))


def field(region, access, update, entries):
    body = path(region) + bytes([access | (update << 5)])
    for entry, bits in entries:
        body += (entry.encode() if entry else b"\x00") + pkg_length(bits, False)
    return block(b"\x5b\x81", body)


def op_region(target, space, offset, length):
    return b"\x5b\x80" + path(target) + bytes([space]) + num(offset) + num(length)


def if_(predicate, *children):
    return block(b"\xa0", predicate + b"".join(children))


def else_(*children):
    return block(b"\xa1", b"".join(children))


def while_(predicate, *children):
    return block(b"\xa2", predicate + b"".join(children))


def equal(a, b):
    return b"\x93" + a + b


def not_equal(a, b):
    return b"\x92\x93" + a + b


def less(a, b):
    return b"\x95" + a + b


def arg(n):
    return bytes([0x68 + n])


def local(n):
    return bytes([0x60 + n])


def store(target, value):
    return b"\x70" + value + target


def binary(opcode, target, a, b):
    return bytes([opcode]) + a + b + target


def add_and(target, a, b):
    return binary(0x7B, target, a, b)


def add_or(target, a, b):
    return binary(0x7D, target, a, b)


def shift_left(target, a, b):
    return binary(0x79, target, a, b)


def index(target, source, at):
    return binary(0x88, target, source, at)


def create_dword(target, source, at):
    return binary(0x8A, target, source, at)


def subtract(target, a, b):
    return binary(0x74, target, a, b)


def ret(value):
    return b"\xa4" + value


def deref(value):
    return b"\x83" + value


def size_of(value):
    return b"\x87" + value


def increment(value):
    return b"\x75" + value


def lnot(value):
    return b"\x92" + value


def land(a, b):
    return b"\x90" + a + b


def lor(a, b):
    return b"\x91" + a + b


def mutex(target, level):
    return b"\x5b\x01" + path(target) + bytes([level])


def acquire(target, timeout=0xFFFF):
    return b"\x5b\x23" + path(target) + u16(timeout)


def release(target):
    return b"\x5b\x27" + path(target)


def notify(target, value):
    return b"\x86" + target + value


def call(target, *args):
    return path(target) + b"".join(args)


ZERO, ONE, BREAK, DEBUG = b"\x00", b"\x01", b"\xa5", b"\x5b\x31"


def exact_length(value):
    if value < 0x40:
        return bytes([value])
    follow = 1 if value < 0x1000 else 2 if value < 0x100000 else 3
    return bytes([(follow << 6) | (value & 0x0F)]) + bytes((value >> (4 + 8 * i)) & 0xFF for i in range(follow))


def exact_package(opcode, body):
    total = len(body) + 1
    while True:
        length = exact_length(total)
        if len(body) + len(length) == total:
            return opcode + length + body
        total = len(body) + len(length)


def exact_integer(value):
    if value in (0, 1):
        return bytes([value])
    if value <= 0xFF:
        return b"\x0a" + bytes([value])
    if value <= 0xFFFF:
        return b"\x0b" + u16(value)
    return b"\x0c" + u32(value)


def processor(number, pxm):
    x2apic = number >= 255
    label = ("C" + format(number & 0xFFF, "03X")).encode()
    body = label + (b"\x08_HID\x0dACPI0007\x00\x08_UID" + exact_integer(number) if x2apic
                    else bytes([number & 0xFF]) + u32(0) + b"\x00")
    body += exact_package(b"\x14", b"_STA\x08\xa4CSTA" + exact_integer(number))
    entry = (bytes([9, 16, 0, 0]) + u32(number) + u32(1) + u32(number) if x2apic
             else bytes([0, 8, number & 0xFF, number & 0xFF]) + u32(1))
    body += b"\x08_MAT" + exact_package(b"\x11", exact_integer(len(entry)) + entry)
    if number:
        body += exact_package(b"\x14", b"_EJ0\x01CEJ0" + exact_integer(number))
    body += exact_package(b"\x14", b"_OST\x0bCOST" + exact_integer(number) + b"\x68\x69\x6a")
    if pxm is not None:
        body += b"\x08_PXM" + exact_integer(pxm)
    return exact_package(b"\x5b\x82" if x2apic else b"\x5b\x83", body)


def debug_port():
    loop = while_(less(local(2), local(1)), store(path("DBGB"), deref(index(ZERO, local(0), local(2)))),
                  increment(local(2)))
    writer = method("DBUG", 1, False, b"\x98" + arg(0) + local(0), b"\x96" + local(0) + local(0),
                    subtract(local(1), size_of(local(0)), ONE), store(local(2), ZERO), loop,
                    store(path("DBGB"), num(0x0A)))
    return root_scope(op_region("DBG_", SYSTEM_IO, 0x402, 1), field("DBG_", BYTE_ACCESS, PRESERVE, [("DBGB", 8)]),
                      writer)


def osc(pci_hotplug):
    cdw1, cdw3 = path("CDW1"), path("CDW3")
    granted = if_(equal(arg(0), to_uuid("33db4d5b-1ff7-401c-9657-7441c03dd766")),
                  create_dword(path("CDW2"), arg(3), num(4)), create_dword(cdw3, arg(3), num(8)),
                  store(local(0), cdw3), add_and(local(0), local(0), num(0x1E if pci_hotplug else 0x1F)),
                  if_(not_equal(arg(1), ONE), add_or(cdw1, cdw1, num(8))),
                  if_(not_equal(cdw3, local(0)), add_or(cdw1, cdw1, num(0x10))), store(cdw3, local(0)))
    return method("_OSC", 4, False, create_dword(cdw1, arg(3), ZERO), granted, else_(add_or(cdw1, cdw1, num(4))),
                  ret(arg(3)))


def edsm():
    slot0 = index(ZERO, local(0), ZERO)
    query = if_(equal(arg(2), ZERO), store(local(0), buffer(b"\x00")),
                if_(not_equal(arg(0), to_uuid("e5c937d0-3553-4d7a-9117-ea4d19c3434d")), ret(local(0))),
                if_(less(arg(1), num(2)), ret(local(0))), store(slot0, num(0x81)), ret(local(0)))
    label = if_(equal(arg(2), num(7)), store(local(0), package(ZERO, string(""))),
                store(local(1), deref(index(ZERO, arg(4), ZERO))), store(slot0, local(1)), ret(local(0)))
    return method("EDSM", 5, True, query, label)


def pci0(pci_hotplug):
    host = device("PCI0", name("_HID", eisa("PNP0A08")), name("_CID", eisa("PNP0A03")), name("_UID", ZERO),
                  osc(pci_hotplug), edsm())
    drac = device("DRAC", name("_HID", string("PNP0C01")),
                  name("_CRS", resources(memory_range(4, NOT_CACHEABLE, 0xE0000000, 0xEFFFFFFF))))
    return scope("_SB_", host, drac)


def pcihp(modern_label):
    registers = (op_region("PCST", SYSTEM_IO, 0x0CC0, 8),
                 field("PCST", DWORD_ACCESS, WRITE_AS_ZEROES, [("PCIU", 32), ("PCID", 32)]),
                 op_region("SEJ_", SYSTEM_IO, 0x0CC8, 4), field("SEJ_", DWORD_ACCESS, WRITE_AS_ZEROES, [("B0EJ", 32)]),
                 op_region("BNMR", SYSTEM_IO, 0x0CD0, 8),
                 field("BNMR", DWORD_ACCESS, WRITE_AS_ZEROES, [("BNUM", 32), ("PIDX", 32)]), mutex("BLCK", 0))
    pcej = method("PCEJ", 2, False, acquire("BLCK"), store(path("BNUM"), arg(0)),
                  store(path("B0EJ"), shift_left(ZERO, ONE, arg(1))), release("BLCK"), ret(ZERO))
    aidx = method("AIDX", 2, False, acquire("BLCK"), store(path("BNUM"), arg(0)),
                  store(path("PIDX"), shift_left(ZERO, ONE, arg(1))), store(local(0), path("PIDX")), release("BLCK"),
                  ret(local(0)))
    read = store(local(2), call("AIDX", deref(index(ZERO, arg(4), ZERO)), deref(index(ZERO, arg(4), ONE))))
    unassigned, invalid = equal(local(2), ZERO), equal(local(2), num(0xFFFFFFFF))
    query = if_(equal(arg(2), ZERO), store(local(0), buffer(b"\x00")),
                if_(not_equal(arg(0), to_uuid("e5c937d0-3553-4d7a-9117-ea4d19c3434d")), ret(local(0))),
                if_(less(arg(1), num(2)), ret(local(0))), store(local(1), ZERO), read,
                if_(lnot(add_or(ZERO, unassigned, invalid)), add_or(local(1), local(1), ONE),
                    add_or(local(1), local(1), shift_left(ZERO, ONE, num(7)))),
                store(index(ZERO, local(0), ZERO), local(1)), ret(local(0)))
    store_index = store(index(ZERO, local(0), ZERO), local(2))
    if modern_label:
        fill = if_(lnot(lor(unassigned, invalid)), store_index, store(index(ZERO, local(0), ONE), string("")))
        label = if_(equal(arg(2), num(7)), read, store(local(0), fixed_package(2)), fill, ret(local(0)))
    else:
        pair = b"\x12" + pkg_length(4) + b"\x02\x00\x0d\x00"
        label = if_(equal(arg(2), num(7)), store(local(0), pair), read, store_index, ret(local(0)))
    return scope("_SB_.PCI0", *registers, pcej, aidx, method("PDSM", 5, True, query, label))


def pic():
    return name("PICF", ZERO) + method("_PIC", 1, False, store(path("PICF"), arg(0)))


def routing_entry(slot, pin, link):
    return package(num((slot << 16) | 0xFFFF), num(pin), path(link), ZERO)


def prt():
    tables = []
    for prefix in ("LNK", "GSI"):
        entries = []
        for slot in range(32):
            base = ord("A") if slot in (0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F) else ord("E")
            head = slot & 3 if slot < 0x18 else 0
            entries += [routing_entry(slot, pin, prefix + chr(base + (head + pin) % 4)) for pin in range(4)]
        tables.append(package(*entries))
    choose = method("_PRT", 0, False, if_(equal(path("PICF"), ZERO), ret(path("PRTP"))), else_(ret(path("PRTA"))))
    return scope("PCI0", name("PRTP", tables[0]), name("PRTA", tables[1]), choose)


def links(edge):
    status = method("IQST", 1, False, if_(add_and(ZERO, num(0x80), arg(0)), ret(num(9))), ret(num(0x0B)))
    resource = method("IQCR", 1, True, name("PRR0", resources(interrupts([0], edge))),
                      create_dword(path("PRRI"), path("PRR0"), num(5)), store(path("PRRI"), add_and(ZERO, arg(0), num(0x0F))),
                      ret(path("PRR0")))
    out = status + resource
    for number, letter in enumerate("ABCDEFGH"):
        register = path("PRQ" + letter)
        out += device("LNK" + letter, name("_HID", eisa("PNP0C0F")), name("_UID", num(number)),
                      name("_PRS", resources(interrupts([5, 10, 11], edge))),
                      method("_STA", 0, False, ret(call("IQST", register))),
                      method("_DIS", 0, False, add_or(register, register, num(0x80))),
                      method("_CRS", 0, False, ret(call("IQCR", register))),
                      method("_SRS", 1, False, create_dword(path("PRRI"), arg(0), num(5)), store(register, path("PRRI"))))
    for number, letter in enumerate("ABCDEFGH"):
        gsi = 0x10 + number
        out += device("GSI" + letter, name("_HID", eisa("PNP0C0F")), name("_UID", num(gsi)),
                      name("_PRS", resources(interrupts([gsi], edge))), name("_CRS", resources(interrupts([gsi], edge))),
                      method("_DIS", 0, False), method("_SRS", 1, False))
    return out


def gpe_hid():
    return scope("_GPE", name("_HID", string("ACPI0006")))


def gpe_e02():
    return method("\\_GPE._E02", 0, False, call("\\_SB_.CPUS.CSCN"))


def gpe_e01():
    return scope("_GPE", method("_E01", 0, False))


def hotplug(field_name):
    return path("\\_SB_.PCI0.PRES." + field_name)


def cpu_methods(cpu_count, queued_eject):
    lock, csel, ccmd, cdat = "\\_SB_.PCI0.PRES.CPLK", hotplug("CSEL"), hotplug("CCMD"), hotplug("CDAT")
    cins, crmv = hotplug("CINS"), hotplug("CRMV")
    cases = b"".join(if_(equal(arg(0), num(n)), notify(path("C" + format(n, "03X")), arg(1))) for n in range(cpu_count))
    ctfy = method("CTFY", 2, False, cases)
    csta = method("CSTA", 1, True, acquire(lock), store(csel, arg(0)), store(local(0), ZERO),
                  if_(equal(hotplug("CPEN"), ONE), store(local(0), num(0x0F))), release(lock), ret(local(0)))
    cej0 = method("CEJ0", 1, True, acquire(lock), store(csel, arg(0)), store(hotplug("CEJ0"), ONE), release(lock))
    event, added, position, uid, job, ejects = local(0), local(1), local(2), local(3), local(4), local(5)
    added_full = equal(added, num(255))
    full = lor(added_full, equal(ejects, num(255))) if queued_eject else added_full
    mark = store(event, ONE)
    on_insert = if_(equal(cins, ONE), store(index(ZERO, path("CNEW"), added), uid), increment(added), mark)
    if queued_eject:
        on_remove = if_(equal(crmv, ONE), store(index(ZERO, path("CEJL"), ejects), uid), increment(ejects), mark)
    else:
        on_remove = else_(if_(equal(crmv, ONE), call("CTFY", uid, num(3)), store(crmv, ONE), mark))
    scan = while_(land(equal(event, ONE), less(uid, num(cpu_count))), store(event, ZERO), store(csel, uid),
                  store(ccmd, ZERO), if_(less(cdat, uid), BREAK), if_(full, store(job, ONE), BREAK), store(uid, cdat),
                  on_insert, on_remove, increment(uid))
    notify_added = while_(less(position, added), store(uid, deref(index(ZERO, path("CNEW"), position))),
                          call("CTFY", uid, ONE), store(DEBUG, uid), store(csel, uid), store(cins, ONE),
                          increment(position))
    notify_ejects = while_(less(position, ejects), store(uid, deref(index(ZERO, path("CEJL"), position))),
                           call("CTFY", uid, num(3)), store(csel, uid), store(crmv, ONE), increment(position))
    batch = while_(equal(job, ONE), store(job, ZERO), store(event, ONE), store(added, ZERO),
                   store(ejects, ZERO) if queued_eject else b"", scan, store(position, ZERO), notify_added,
                   store(position, ZERO) if queued_eject else b"", notify_ejects if queued_eject else b"")
    cscn = method("CSCN", 0, True, acquire(lock), name("CNEW", fixed_package(255)),
                  name("CEJL", fixed_package(255)) if queued_eject else b"", store(uid, ZERO), store(job, ONE), batch,
                  release(lock))
    cost = method("COST", 4, True, acquire(lock), store(csel, arg(0)), store(ccmd, ONE), store(cdat, arg(1)),
                  store(ccmd, num(2)), store(cdat, arg(2)), release(lock))
    return ctfy + csta + cej0 + cscn + cost


def cpus(cpu_count, nodes, initialize_selector, queued_eject):
    flags = [("", 32), ("CPEN", 1), ("CINS", 1), ("CRMV", 1), ("CEJ0", 1), ("CEJF", 1), ("", 3), ("CCMD", 8)]
    resource = device("\\_SB_.PCI0.PRES", name("_HID", eisa("PNP0A06")), name("_UID", string("CPU Hotplug resources")),
                      mutex("CPLK", 0), name("_CRS", resources(io(0x0CD8, 0x0CD8, 1, 12))),
                      op_region("PRST", SYSTEM_IO, 0x0CD8, 12), field("PRST", BYTE_ACCESS, WRITE_AS_ZEROES, flags),
                      field("PRST", DWORD_ACCESS, PRESERVE, [("CSEL", 32), ("", 32), ("CDAT", 32)]),
                      method("_INI", 0, True, store(path("CSEL"), ZERO)) if initialize_selector else b"")
    per_node = cpu_count // max(nodes, 1)
    objects = b"".join(processor(n, n // per_node if nodes else None) for n in range(cpu_count))
    container = device("\\_SB_.CPUS", name("_HID", string("ACPI0010")), name("_CID", eisa("PNP0A05")),
                       cpu_methods(cpu_count, queued_eject), objects)
    return resource + container


def pxb_routing():
    return package(*[routing_entry(slot, pin, "LNK" + chr(ord("A") + ((slot + pin + 3) & 3)))
                     for slot in range(32) for pin in range(4)])


def pxbs(nodes):
    out = b""
    for pxm, node in reversed(list(enumerate(nodes))):
        bus = node.get("pxb_bus")
        if bus is None:
            continue
        bridge = device("PC" + format(bus, "02X"), name("_UID", num(bus)), name("_BBN", num(bus)),
                        name("_HID", eisa("PNP0A08")), name("_CID", eisa("PNP0A03")), osc(False), name("_PXM", num(pxm)),
                        method("_PRT", 0, False, ret(pxb_routing())),
                        name("_CRS", resources(address_space(2, BUS_NUMBER, 0, bus, bus))))
        out += scope("\\_SB_", bridge)
    return out


def reservation(label, description, base, length):
    return device(label, name("_HID", string("PNP0A06")), name("_UID", string(description)), name("_STA", num(0x0B)),
                  name("_CRS", resources(io(base, base, 1, length))))


def crs(low_ram_end, hole64, pci_hotplug, bus_max):
    hole64 = 0x0000_0008_0000_0000 if hole64 is None else hole64
    pci64 = b"\x8a" + u16(43) + bytes([0, 0x0C, 0x03]) + u64(0) + u64(0x0000_3800_0000_0000) \
        + u64(0x0000_3800_0000_0000 + hole64 - 1) + u64(0) + u64(hole64)
    template = resources(address_space(2, BUS_NUMBER, 0, 0, bus_max), io(0x0CF8, 0x0CF8, 1, 8),
                         address_space(2, IO_RANGE, 3, 0x0000, 0x0CF7), address_space(2, IO_RANGE, 3, 0x0D00, 0xFFFF),
                         memory_range(4, CACHEABLE, 0x000A0000, 0x000BFFFF),
                         memory_range(4, NOT_CACHEABLE, low_ram_end, 0xDFFFFFFF),
                         memory_range(4, NOT_CACHEABLE, 0xF0000000, 0xFEBFFFFF), pci64)
    out = name("_CRS", template) + reservation("GPE0", "GPE0 resources", 0x0620, 0x10)
    return out + (reservation("PHPR", "PCI Hotplug resources", 0x0CC0, 0x18) if pci_hotplug else b"")


def sleep_states():
    return root_scope(name("_S3_", package(ONE, ONE, ZERO, ZERO)), name("_S4_", package(num(2), num(2), ZERO, ZERO)),
                      name("_S5_", package(ZERO, ZERO, ZERO, ZERO)))


def fw_cfg_device():
    return scope("\\_SB_.PCI0", device("FWCF", name("_HID", string("QEMU0002")), name("_STA", num(0x0B)),
                                       name("_CRS", resources(io(0x510, 0x510, 1, 12)))))


def isa_device(label, hid, uid, sta, *descriptors):
    return device(label, name("_HID", eisa(hid)), name("_UID", num(uid)) if uid is not None else b"",
                  name("_STA", num(sta)) if sta is not None else b"", name("_CRS", resources(*descriptors)))


def lpc(modern_serial_irq):
    routing = field("PCI0.SF8_.PIRQ", BYTE_ACCESS, PRESERVE,
                    [("PRQA", 8), ("PRQB", 8), ("PRQC", 8), ("PRQD", 8), ("", 0x20), ("PRQE", 8), ("PRQF", 8),
                     ("PRQG", 8), ("PRQH", 8)])
    return (op_region("PIRQ", PCI_CONFIG, 0x60, 0x0C) + scope("\\_SB_", routing)
            + isa_device("KBD_", "PNP0303", None, 0x0F, io(0x60, 0x60, 1, 1), io(0x64, 0x64, 1, 1), irq(1))
            + isa_device("MOU_", "PNP0F13", None, 0x0F, irq(12))
            + isa_device("COM1", "PNP0501", 1, 0x0F, io(0x3F8, 0x3F8, 0, 8),
                         irq(4, (1 << 3) | (1 << 4)) if modern_serial_irq else irq(4))
            + isa_device("RTC_", "PNP0B00", None, None, io(0x70, 0x70, 1, 8), irq(8)))


def root_bus(slot_count, trailing, modern_serial_irq, pxb_count):
    devices = [(slot * 8, False) for slot in range(slot_count)]
    pxb_slots = range(FIRST_PXB_SLOT, FIRST_PXB_SLOT + pxb_count)
    devices += [(slot * 8, False) for slot in pxb_slots]
    slot = slot_count
    for kind in trailing:
        while slot in pxb_slots:
            slot += 1
        devices.append(((slot * 8) & 0xFF, kind == ROOT_PORT))
        slot += 1
    devices += [(0xF8, False), (0xFA, False), (0xFB, False)]
    children = lpc(modern_serial_irq)
    bus = b""
    for devfn, root_port in sorted(devices, key=lambda d: d[0]):
        address = ((devfn >> 3) << 16) | (devfn & 7)
        bus += device("S" + format(devfn, "02X") + "_", name("_ADR", num(address)),
                      children if devfn == 0xF8 else b"", device("S00_", name("_ADR", ZERO)) if root_port else b"")
    return scope("\\_SB_", scope("PCI0", bus))


def root_bus_limit(buses):
    limit = 0xFF
    for bus in reversed(buses):
        if bus < limit:
            limit = bus - 1
    return limit


def dsdt(config):
    profile = compatibility(config["qemu_version"])
    pci_hotplug, nodes = not config["hotplug_off"], numa_layout(config)
    buses = [n["pxb_bus"] for n in nodes if n.get("pxb_bus") is not None]
    low_ram_end = 0x80000000 if config["memory_size"] >= 0xB0000000 else config["memory_size"]
    slots = 4 + config["root_verity"] + config["num_nics"] + config["num_verity_volumes"]
    ports = config["num_nvswitches"] + (0 if buses else config["num_gpus"])
    trailing = [ROOT_PORT] * ports + list(config["extra_root_devices"])
    legacy_label = profile in (V8, V9_PRE_92)
    body = debug_port() + pci0(pci_hotplug) + (pcihp(not legacy_label) if pci_hotplug else b"") + pic()
    body += scope("_SB_", prt(), links(legacy_label)) + gpe_hid()
    body += scope("_SB_", cpus(config["cpu_count"], len(nodes), profile in (V8, V9_PRE_92, V9_2, V10),
                               profile in (V10, V11_0, V11_1)))
    body += gpe_e02() + pxbs(nodes)
    body += scope("\\_SB_.PCI0", crs(low_ram_end, config["pci_hole64_size"], pci_hotplug, root_bus_limit(buses)))
    body += sleep_states() + fw_cfg_device() + root_bus(slots, trailing, profile == V11_1, len(buses))
    body += gpe_e01() if pci_hotplug else b""
    return header(b"DSDT", 36 + len(body), 1) + body


def header(signature, length, revision):
    return signature + u32(length) + bytes([revision, 0]) + b"BOCHS BXPC    " + u32(1) + b"BXPC" + u32(1)


def table(signature, length, revision):
    return bytearray(header(signature, length, revision) + bytes(length - 36))


def facs():
    return b"FACS" + u32(64) + bytes(56)


def gas(out, at, width, address):
    out[at], out[at + 1] = 1, width
    out[at + 4:at + 12] = u64(address)


def fadt(smm, cpu_count):
    out = table(b"FACP", 244, 3)
    out[40:44] = u32(64)
    out[44] = 1
    out[46:48] = u16(9)
    if smm:
        out[48:52], out[52], out[53] = u32(0xB2), 2, 3
    out[56:60], out[64:68], out[76:80], out[80:84] = u32(0x600), u32(0x604), u32(0x608), u32(0x620)
    out[88], out[89], out[91], out[92] = 4, 2, 4, 16
    out[96:98], out[98:100] = u16(0x0FFF), u16(0x0FFF)
    out[108] = 0x32
    out[109:111] = u16(2)
    flags = (1 << 0) | (1 << 2) | (1 << 5) | (1 << 7) | (1 << 10) | (1 << 15) | ((1 << 18) if cpu_count > 8 else 0)
    out[112:116] = u32(flags)
    out[116], out[117] = 1, 8
    out[120:128] = u64(0x0CF9)
    out[128] = 0x0F
    out[140:148] = u64(64)
    gas(out, 148, 32, 0x600)
    gas(out, 172, 16, 0x604)
    gas(out, 208, 32, 0x608)
    gas(out, 220, 128, 0x620)
    return bytes(out)


def madt(cpu_count, pic_mode, legacy_overrides):
    legacy, x2apic = min(cpu_count, 255), max(cpu_count - 255, 0)
    cpu_bytes = legacy * 8 + x2apic * 16
    tail = 172 if legacy_overrides else 62
    out = table(b"APIC", 44 + cpu_bytes + tail + (6 if cpu_count <= 255 else 12), 3)
    out[36:40], out[40:44] = u32(0xFEE00000), u32(int(pic_mode))
    for n in range(cpu_count):
        if n < 255:
            out[44 + n * 8:52 + n * 8] = bytes([0, 8, n, n]) + u32(1)
        else:
            at = 44 + legacy * 8 + (n - 255) * 16
            out[at:at + 16] = bytes([9, 16, 0, 0]) + u32(n) + u32(1) + u32(n)
    at = 44 + cpu_bytes
    out[at:at + 8] = bytes([1, 12, 0, 0]) + u32(0xFEC00000)
    if legacy_overrides:
        for source in range(16):
            entry = at + 12 + source * 10
            out[entry:entry + 10] = bytes([2, 10, 0, source]) + u32(2 if source == 0 else source) + u16(5)
    else:
        out[at + 12:at + 22] = bytes([2, 10, 0, 0, 2, 0, 0, 0, 0, 0])
        for n, source in enumerate((5, 9, 10, 11)):
            entry = at + 22 + n * 10
            out[entry:entry + 10] = bytes([2, 10, 0, source]) + u32(source) + u16(13)
    lint = at + tail
    if cpu_count <= 255:
        out[lint:lint + 6] = bytes([4, 6, 0xFF, 0, 0, 1])
    else:
        out[lint:lint + 12] = bytes([0x0A, 12, 0, 0]) + u32(0xFFFFFFFF) + bytes([1, 0, 0, 0])
    return bytes(out)


def mcfg():
    out = table(b"MCFG", 60, 1)
    out[44:52] = u64(0xE0000000)
    out[55] = 0xFF
    return bytes(out)


def waet():
    out = table(b"WAET", 40, 1)
    out[36:40] = u32(2)
    return bytes(out)


def rsdt(entries):
    out = table(b"RSDT", 36 + 4 * len(entries), 1)
    for n, entry in enumerate(entries):
        out[36 + 4 * n:40 + 4 * n] = u32(entry)
    return bytes(out)


def memory_affinity(base, length, node, enabled):
    return bytes([1, 40]) + u32(node) + u16(0) + u64(base) + u64(length) + u32(0) + u32(int(enabled)) + u64(0)


def srat(cpu_count, memory, hole64, nodes):
    body = b""
    per_node = cpu_count // nodes
    for n in range(cpu_count):
        node = n // per_node
        body += (bytes([0, 16, node & 0xFF, n]) + u32(1) + bytes(4) + u32(0) if n < 255
                 else bytes([2, 24]) + u16(0) + u32(node) + u32(n) + u32(1) + u32(0) + u32(0))
    below = 0x80000000 if memory >= 0xB0000000 else memory
    high_end = min(0x100000000 + memory - below, 2 ** 64 - 1)
    hole_start = min(high_end + (1 << 30) - 1, 2 ** 64 - 1) & ~((1 << 30) - 1)
    max_used = max(min(hole_start + (hole64 if hole64 is not None else 1 << 35), 2 ** 64 - 1) - 1, 0)
    above = 0x10000000000 if max_used >= 0xFD00000000 else 0x100000000
    entries, next_base = 0, 0
    for node in range(nodes):
        base, length = next_base, memory // nodes
        next_base = min(base + length, 2 ** 64 - 1)
        if base <= 0xA0000 < next_base:
            length -= next_base - 0xA0000
            if length > 0:
                body += memory_affinity(base, length, node, True)
                entries += 1
            if next_base <= 0x100000:
                next_base = 0x100000
                continue
            base, length = 0x100000, next_base - 0x100000
        if base <= below < next_base:
            length -= next_base - below
            if length > 0:
                body += memory_affinity(base, length, node, True)
                entries += 1
            base, length = above, next_base - below
            next_base = min(base + length, 2 ** 64 - 1)
        if length > 0:
            body += memory_affinity(base, length, node, True)
            entries += 1
    body += memory_affinity(0, 0, 0, False) * max(nodes + 2 - entries, 0)
    out = header(b"SRAT", 48 + len(body), 1)
    return out[:8] + bytes([1, 0]) + out[10:] + u32(1) + u64(0) + body


def loader_command(*fields):
    data = b"".join(fields)
    return data + bytes(128 - len(data))


def file_name(text):
    return text.encode().ljust(56, b"\0")


def allocate(file, alignment, zone):
    return loader_command(u32(1), file_name(file), u32(alignment), bytes([zone]))


def add_pointer(destination, source, offset, size):
    return loader_command(u32(2), file_name(destination), file_name(source), u32(offset), bytes([size]))


def add_checksum(file, offset, start, length):
    return loader_command(u32(3), file_name(file), u32(offset), u32(start), u32(length))


def locations(tables):
    found, offset = {}, 0
    while offset < len(tables) and tables[offset:offset + 4] != bytes(4):
        length = struct.unpack_from("<I", tables, offset + 4)[0]
        if length < 36 or offset + length > len(tables):
            raise ValueError("malformed generated ACPI table")
        found.setdefault(tables[offset:offset + 4], (offset, length))
        offset += length
    return found


def finish(tables):
    found = locations(tables)
    files = "etc/acpi/tables"

    def checksum(signature):
        offset, length = found[signature]
        return add_checksum(files, offset + 9, offset, length)
    rsdt_offset, rsdt_length = found[b"RSDT"]
    loader = allocate("etc/acpi/rsdp", 16, 2) + allocate(files, 64, 1) + checksum(b"DSDT")
    loader += b"".join(add_pointer(files, files, found[b"FACP"][0] + at, size) for at, size in ((36, 4), (40, 4), (140, 8)))
    loader += checksum(b"FACP") + checksum(b"APIC") + (checksum(b"SRAT") if b"SRAT" in found else b"")
    loader += checksum(b"MCFG") + checksum(b"WAET")
    loader += b"".join(add_pointer(files, files, rsdt_offset + at, 4) for at in range(36, rsdt_length, 4))
    loader += checksum(b"RSDT") + add_pointer("etc/acpi/rsdp", files, 16, 4) + add_checksum("etc/acpi/rsdp", 8, 0, 20)
    if len(loader) > LOADER_BLOB_SIZE:
        raise ValueError("the fw_cfg loader exceeds QEMU's allocation")
    return {"tables": tables, "rsdp": b"RSD PTR \0BOCHS \0" + u32(rsdt_offset), "loader": loader.ljust(LOADER_BLOB_SIZE, b"\0")}


def numa_layout(config):
    if config["numa_nodes"] or not config["hugepages"]:
        return list(config["numa_nodes"])
    return [{"pxb_bus": LEGACY_PXB_BUS if config["num_gpus"] > 0 else None}]


def validate(config):
    if config["cpu_count"] <= 0 or config["memory_size"] <= 0:
        raise TopologyError("the VM has no vCPU or no memory")
    if config["cpu_count"] > 4096:
        raise TopologyError("more than 4096 vCPUs")
    nodes = config["numa_nodes"]
    if nodes:
        if len(nodes) > 128:
            raise TopologyError("more than 128 NUMA nodes")
        expanders = [n.get("pxb_bus") for n in nodes if n.get("pxb_bus") is not None]
        if expanders and len(expanders) != len(nodes):
            raise TopologyError("NUMA nodes must all have a PXB expander or none")
        if config["cpu_count"] % len(nodes) or config["memory_size"] % len(nodes):
            raise TopologyError("vCPUs and memory do not split evenly across the NUMA nodes")
        if len(expanders) > LPC_SLOT - FIRST_PXB_SLOT or len(set(expanders)) != len(expanders) or 0 in expanders:
            raise TopologyError("invalid PXB bus numbers")
    buses = [n["pxb_bus"] for n in numa_layout(config) if n.get("pxb_bus") is not None]
    if len(buses) == 1 and config["num_gpus"] > 32:
        raise TopologyError("more than 32 GPU root ports on the PXB")
    if buses and 4 + config["root_verity"] + config["num_nics"] + config["num_verity_volumes"] > 16:
        raise TopologyError("too many devices before the fixed-address PXB")
    ports = config["num_nvswitches"] + (0 if buses else config["num_gpus"])
    extra = config["extra_root_devices"]
    if config["num_nics"] + config["num_verity_volumes"] + config["root_verity"] - 1 + ports + len(extra) > 26 - len(buses):
        raise TopologyError("too many devices on the root PCIe bus")
    if config["num_nvswitches"] and not config["num_gpus"]:
        raise TopologyError("NVSwitch passthrough without a GPU")
    if not config["hotplug_off"] and ports + sum(1 for d in extra if d == ROOT_PORT):
        raise TopologyError("PCI hotplug with root ports is not modelled")


def machine(vm):
    version = vm.get("qemu_version") or "9.1.0"
    parts = tuple(int(p) for p in str(version).split("."))
    if len(parts) != 3:
        raise TopologyError("unexpected QEMU version " + repr(version))
    if vm.get("swtpm"):
        raise TopologyError("swtpm is not modelled")
    if vm.get("host_share_mode", "") not in ("", "9p", "vvfat", "vhd"):
        raise TopologyError("unexpected shared disk mode " + repr(vm.get("host_share_mode")))
    extra = vm.get("extra_root_devices") or []
    if any(d not in (ENDPOINT, ROOT_PORT) for d in extra):
        raise TopologyError("unexpected root bus device")
    config = {"qemu_version": parts, "cpu_count": int(vm.get("cpu_count") or 0), "memory_size": int(vm.get("memory_size") or 0),
              "pic": vm["pic"] if vm.get("pic") is not None else (8, 0, 0) <= parts < (9, 0, 0), "smm": False,
              "hugepages": bool(vm.get("hugepages")), "numa_nodes": [dict(n) for n in vm.get("numa_nodes") or []],
              "num_gpus": int(vm.get("num_gpus") or 0), "num_nvswitches": int(vm.get("num_nvswitches") or 0),
              "num_nics": int(vm["num_nics"]) if vm.get("num_nics") is not None else 1,
              "num_verity_volumes": int(vm.get("num_verity_volumes") or 0), "extra_root_devices": list(extra),
              "hotplug_off": bool(vm.get("hotplug_off")), "root_verity": True,
              "pci_hole64_size": int(vm["pci_hole64_size"]) if vm.get("pci_hole64_size") else None}
    compatibility(parts)
    return config


def build(config):
    validate(config)
    nodes = numa_layout(config)
    tables = facs() + dsdt(config)
    entries = [len(tables)]
    tables += fadt(config["smm"], config["cpu_count"])
    entries.append(len(tables))
    tables += madt(config["cpu_count"], config["pic"], compatibility(config["qemu_version"]) in (V8, V9_PRE_92))
    if nodes:
        entries.append(len(tables))
        tables += srat(config["cpu_count"], config["memory_size"], config["pci_hole64_size"], len(nodes))
    entries.append(len(tables))
    tables += mcfg()
    entries.append(len(tables))
    tables += waet()
    tables += rsdt(entries)
    return finish(tables + bytes(-len(tables) % TABLE_BLOB_SIZE))
