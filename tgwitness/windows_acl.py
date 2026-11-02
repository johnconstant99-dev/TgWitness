"""Inspect and replace data-directory ACLs using Windows' locale-independent APIs."""
import ctypes
from ctypes import wintypes
from pathlib import Path


FILE_ALL_ACCESS = 0x1F01FF
OWNER_INFORMATION = 1
DACL_INFORMATION = 4
PROTECTED_DACL_INFORMATION = 0x80000000
SE_DACL_PROTECTED = 0x1000
REPARSE_POINT = 0x400


class AclSize(ctypes.Structure):
    _fields_ = [(name, wintypes.DWORD) for name in ("count", "used", "free")]


class AllowedAce(ctypes.Structure):
    _fields_ = [("kind", wintypes.BYTE), ("flags", wintypes.BYTE),
                ("size", wintypes.WORD), ("mask", wintypes.DWORD), ("sid", wintypes.DWORD)]


class WindowsAcl:
    def __init__(self, sid):
        self.api = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        ptr, dword = ctypes.c_void_p, wintypes.DWORD
        self.kernel.LocalFree.argtypes, self.kernel.LocalFree.restype = [ptr], ptr
        signatures = {
            "ConvertStringSidToSidW": ([wintypes.LPCWSTR, ctypes.POINTER(ptr)], wintypes.BOOL),
            "ConvertStringSecurityDescriptorToSecurityDescriptorW":
                ([wintypes.LPCWSTR, dword, ctypes.POINTER(ptr), ctypes.POINTER(dword)], wintypes.BOOL),
            "GetSecurityDescriptorDacl":
                ([ptr, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ptr), ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
            "GetSecurityDescriptorControl": ([ptr, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(dword)], wintypes.BOOL),
            "GetNamedSecurityInfoW": ([wintypes.LPWSTR, dword, dword, ctypes.POINTER(ptr),
                                      ctypes.POINTER(ptr), ctypes.POINTER(ptr), ctypes.POINTER(ptr),
                                      ctypes.POINTER(ptr)], dword),
            "SetNamedSecurityInfoW": ([wintypes.LPWSTR, dword, dword, ptr, ptr, ptr, ptr], dword),
            "GetAclInformation": ([ptr, ptr, dword, dword], wintypes.BOOL),
            "GetAce": ([ptr, dword, ctypes.POINTER(ptr)], wintypes.BOOL),
            "EqualSid": ([ptr, ptr], wintypes.BOOL),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.api, name)
            fn.argtypes, fn.restype = args, result
        self.sid = ptr()
        self.check(self.api.ConvertStringSidToSidW(sid, ctypes.byref(self.sid)))
        self.administrators = ptr()
        self.check(self.api.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(self.administrators)))
        self.sddl = "D:P(A;OICI;FA;;;" + sid + ")"

    @staticmethod
    def check(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        self.kernel.LocalFree(self.sid)
        self.kernel.LocalFree(self.administrators)

    def restricted(self, path, *, protected=False):
        owner, acl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        error = self.api.GetNamedSecurityInfoW(str(path), 1, OWNER_INFORMATION | DACL_INFORMATION,
                                              ctypes.byref(owner), None, ctypes.byref(acl), None,
                                              ctypes.byref(descriptor))
        if error:
            raise ctypes.WinError(error)
        try:
            # Elevated Windows processes create children owned by Administrators.
            # That privileged group can already take ownership of any local file;
            # do not accept an unrelated ordinary account as an alternate owner.
            if not acl or not owner or not (self.api.EqualSid(owner, self.sid)
                                           or self.api.EqualSid(owner, self.administrators)):
                return False
            control, revision = wintypes.WORD(), wintypes.DWORD()
            self.check(self.api.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)))
            if protected and not control.value & SE_DACL_PROTECTED:
                return False
            info = AclSize()
            self.check(self.api.GetAclInformation(acl, ctypes.byref(info), ctypes.sizeof(info), 2))
            effective = inheritable = False
            for index in range(info.count):
                pointer = ctypes.c_void_p()
                self.check(self.api.GetAce(acl, index, ctypes.byref(pointer)))
                ace = ctypes.cast(pointer, ctypes.POINTER(AllowedAce)).contents
                # Do not infer safety from unfamiliar object/callback ACEs.
                if ace.kind != 0 or not self.api.EqualSid(pointer.value + AllowedAce.sid.offset, self.sid):
                    return False
                if not ace.flags & 0x08 and ace.mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS:
                    effective = True
                    if ace.flags & 0x07 == 0x03:  # OI + CI, without NO_PROPAGATE
                        inheritable = True
            return effective and (not path.is_dir() or inheritable)
        finally:
            self.kernel.LocalFree(descriptor)

    def restrict(self, path):
        descriptor, acl = ctypes.c_void_p(), ctypes.c_void_p()
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        self.check(self.api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            self.sddl, 1, ctypes.byref(descriptor), None))
        try:
            self.check(self.api.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(acl),
                                                          ctypes.byref(defaulted)))
            error = self.api.SetNamedSecurityInfoW(str(path), 1,
                OWNER_INFORMATION | DACL_INFORMATION | PROTECTED_DACL_INFORMATION, self.sid, None, acl, None)
            if error:
                raise ctypes.WinError(error)
        finally:
            self.kernel.LocalFree(descriptor)


def paths(root):
    """Never change a link target outside the data directory."""
    pending = [Path(root)]
    while pending:
        path = pending.pop()
        if getattr(path.lstat(), "st_file_attributes", 0) & REPARSE_POINT:
            raise OSError("Data directory contains a filesystem link; its permissions were not changed")
        yield path
        if path.is_dir():
            pending.extend(path.iterdir())


def owner_acl(root, sid, *, repair=False):
    # SetNamedSecurityInfo propagates inheritance before the next path is visited.
    # Preflight the entire tree first so an external hardlink cannot have its
    # shared security descriptor changed as a side effect of restricting root.
    linked = {}
    for path in paths(root):
        info = path.lstat()
        if path.is_file() and info.st_nlink > 1:
            key = (info.st_dev, info.st_ino)
            count, expected = linked.get(key, (0, info.st_nlink))
            if expected != info.st_nlink:
                raise OSError("Data directory links changed during permission inspection")
            linked[key] = (count + 1, expected)
    if any(count != expected for count, expected in linked.values()):
        raise OSError("Data directory contains a hardlink outside its tree; its permissions were not changed")
    acl = WindowsAcl(sid)
    try:
        for path in paths(root):
            if not acl.restricted(path, protected=path == Path(root)):
                if not repair:
                    return False
                acl.restrict(path)
                if not acl.restricted(path, protected=True):
                    return False
        return True
    finally:
        acl.close()
