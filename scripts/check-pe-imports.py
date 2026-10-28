#!/usr/bin/env python3
r"""Fail CI when a Windows artifact imports a DLL a clean Windows does not have.

The bug this exists to stop: v0.5.15 shipped, a user on a fresh Windows ran
`opencrabs.exe`, and it died before the first line of its own output with
"VCRUNTIME140_1.dll was not found" / "VCOMP140.DLL was not found". Both come
from the MSVC runtime, which is not part of Windows: it arrives with Visual
Studio, the Office installer, or an explicit vc_redist install (`+crt-static`
in the build would have removed the first, OpenMP off the second). The dialog
told the user to reinstall the program, which was never the problem.

The gate is import-table archaeology, not a smoke run. `windows-latest` ships
the vc_redist 14.x pre-installed, so "the exe starts on the runner" is TRUE for
a binary that cannot start anywhere else. The bytes are the only honest signal,
and they can be read on any OS, which is why this runs on ubuntu and needs no
dumpbin, no wine, no Windows runner.

Rules
  crt           VCRUNTIME140*.dll, MSVCP140*.dll, VCOMP140.dll, CONCRT140.dll.
                Never present on a stock Windows; always a build defect.
  system        Any other import must be in SYSTEM_DLLS (or api-ms-win-* /
                ext-ms-win-*), i.e. shipped with Windows itself. Anything else
                is reported as unknown: a third-party DLL would have to be
                vendored next to the exe, which this project does not do.

Usage
  scripts/check-pe-imports.py dist/*.exe
  scripts/check-pe-imports.py --zip opencrabs-v0.5.15-windows-amd64.zip
  scripts/check-pe-imports.py --self-test

Exit code is 0 only when every scanned binary is clean. The self-test builds
synthetic PE files in memory (a clean one and a polluting one) so the checker
is exercised on a machine with no Windows binary at hand.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zipfile
from pathlib import Path

# The MSVC runtime family. Absent from every stock Windows install.
CRT_DLLS = {
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "vcruntime140_1d.dll",
    "vcruntime140d.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "msvcp140_atomic_wait.dll",
    "msvcp140_codecvt_ids.dll",
    "msvcp140d.dll",
    "vcomp140.dll",
    "vcomp140d.dll",
    "concrt140.dll",
    "msvcr100.dll",
    "msvcr110.dll",
    "msvcr120.dll",
}

# Shipped with Windows 10/11 (or by every supported build of it). Deliberately
# conservative: an import that is not here and is not an api-ms-win-* forwarder
# gets reported, because "it happened to be on the runner" is not a promise.
SYSTEM_DLLS = {
    "advapi32.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "cabinet.dll",
    "combase.dll",
    "comctl32.dll",
    "comdlg32.dll",
    "crypt32.dll",
    "dnsapi.dll",
    "gdi32.dll",
    "gdiplus.dll",
    "iphlpapi.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "mpr.dll",
    "msimg32.dll",
    "msvcrt.dll",
    "ncrypt.dll",
    "netapi32.dll",
    "ntdll.dll",
    "ole32.dll",
    "oleaut32.dll",
    "psapi.dll",
    "rpcrt4.dll",
    "secur32.dll",
    "setupapi.dll",
    "shell32.dll",
    "shlwapi.dll",
    "sspicli.dll",
    "user32.dll",
    "userenv.dll",
    "usp10.dll",
    "uxtheme.dll",
    "version.dll",
    "winhttp.dll",
    "wininet.dll",
    "winmm.dll",
    "wintrust.dll",
    "ws2_32.dll",
    "wtsapi32.dll",
    # The UCRT ships with Windows 10+, so these are not the v0.5.15 failure.
    # They are listed to stay honest: if a build reaches for them, it is
    # dynamic-CRT, which is a size/style question, not a crash.
    "ucrtbase.dll",
    "api-ms-win-crt-runtime-l1-1-0.dll",
}

SYSTEM_PREFIXES = ("api-ms-win-", "ext-ms-win-")


class PEError(Exception):
    pass


def _sections(data: bytes) -> tuple[int, list[tuple[int, int, int, int]]]:
    """Return (import_dir_rva, [(vaddr, vsize, rawptr, rawsize), ...])."""
    if data[:2] != b"MZ":
        raise PEError("missing MZ header")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise PEError("missing PE signature")
    coff = e_lfanew + 4
    nsections, opt_size = struct.unpack_from("<H", data, coff + 2)[0], struct.unpack_from(
        "<H", data, coff + 16
    )[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:  # PE32+
        n_dirs_off, dirs_off = opt + 108, opt + 112
    elif magic == 0x10B:  # PE32
        n_dirs_off, dirs_off = opt + 92, opt + 96
    else:
        raise PEError(f"unknown optional-header magic 0x{magic:x}")
    if struct.unpack_from("<I", data, n_dirs_off)[0] < 2:
        return 0, []
    import_rva = struct.unpack_from("<I", data, dirs_off + 8)[0]
    sections = []
    for i in range(nsections):
        base = opt + opt_size + i * 40
        # Section header field order is VirtualSize, VirtualAddress,
        # SizeOfRawData, PointerToRawData. Reading it as vaddr-first silently
        # mis-maps every RVA, which is how the first version of this script
        # "read" garbage DLL names out of a real exe.
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
        sections.append((vaddr, vsize, rawptr, rawsize))
    return import_rva, sections


def _rva_to_offset(rva: int, sections: list[tuple[int, int, int, int]]) -> int | None:
    for vaddr, vsize, rawptr, rawsize in sections:
        span = max(vsize, rawsize)
        if vaddr <= rva < vaddr + span:
            delta = rva - vaddr
            if delta >= rawsize:
                return None
            return rawptr + delta
    return None


def imported_dlls(data: bytes) -> list[str]:
    """Every DLL named in the PE import directory, in table order."""
    import_rva, sections = _sections(data)
    if not import_rva:
        return []
    offset = _rva_to_offset(import_rva, sections)
    if offset is None:
        raise PEError("import directory RVA is not backed by a section")
    names: list[str] = []
    while True:
        if offset + 20 > len(data):
            raise PEError("truncated import descriptor")
        ilt, _ts, _fwd, name_rva, iat = struct.unpack_from("<IIIII", data, offset)
        if not (ilt or name_rva or iat):
            break
        name_off = _rva_to_offset(name_rva, sections) if name_rva else None
        if name_off is None:
            raise PEError(f"unreadable DLL name RVA 0x{name_rva:x}")
        end = data.find(b"\0", name_off)
        if end < 0:
            raise PEError("unterminated DLL name")
        names.append(data[name_off:end].decode("ascii", "replace"))
        offset += 20
    return names


def classify(dll: str) -> str:
    """'crt', 'system' or 'unknown'."""
    low = dll.lower()
    if low in CRT_DLLS or low.startswith("vcruntime14"):
        return "crt"
    if low in SYSTEM_DLLS or low.startswith(SYSTEM_PREFIXES):
        return "system"
    return "unknown"


def check_binary(label: str, data: bytes) -> list[str]:
    """Print a report per binary; return the human-readable failures."""
    failures: list[str] = []
    try:
        dlls = imported_dlls(data)
    except PEError as exc:
        failures.append(f"{label}: not a readable PE file ({exc})")
        return failures
    if not dlls:
        failures.append(f"{label}: no import table (statically linked? check the build)")
        return failures
    print(f"\n{label}")
    for dll in dlls:
        kind = classify(dll)
        if kind == "crt":
            print(f"  {dll:<40} FAIL  MSVC runtime, absent on a clean Windows")
            failures.append(
                f"{label}: imports {dll}; build with "
                "RUSTFLAGS='-C target-feature=+crt-static' and LLAMA_STATIC_CRT=1"
            )
        elif kind == "unknown":
            print(f"  {dll:<40} FAIL  not a Windows system DLL")
            failures.append(f"{label}: imports {dll}, which is not part of Windows")
        else:
            print(f"  {dll:<40} ok")
    return failures


def check_zip(path: Path) -> list[str]:
    failures: list[str] = []
    found = False
    with zipfile.ZipFile(path) as archive:
        for name in sorted(archive.namelist()):
            if not name.lower().endswith(".exe"):
                continue
            found = True
            failures += check_binary(f"{path.name}:{name}", archive.read(name))
    if not found:
        failures.append(f"{path}: no .exe inside, nothing was checked")
    return failures


def check_path(path: Path) -> list[str]:
    if path.suffix.lower() == ".zip":
        return check_zip(path)
    return check_binary(path.name, path.read_bytes())


def build_minimal_pe(dll_name: str) -> bytes:
    """A one-import PE32+ image, used only by --self-test."""
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x40)
    buf[0x40:0x44] = b"PE\0\0"
    opt = 0x58
    struct.pack_into("<HHIIIHH", buf, 0x44, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", buf, opt, 0x20B)
    struct.pack_into("<I", buf, opt + 108, 16)
    struct.pack_into("<II", buf, opt + 120, 0x1000, 0x28)  # data dir 1: import
    sec = opt + 0xF0
    buf[sec : sec + 8] = b".idata\0\0"
    struct.pack_into("<IIII", buf, sec + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<IIIII", buf, 0x200, 0, 0, 0, 0x1040, 0)
    name = dll_name.encode("ascii") + b"\0"
    buf[0x240 : 0x240 + len(name)] = name
    return bytes(buf)


def self_test() -> list[str]:
    problems = []
    clean = imported_dlls(build_minimal_pe("KERNEL32.dll"))
    if clean != ["KERNEL32.dll"]:
        problems.append(f"self-test: parsed {clean!r}, expected ['KERNEL32.dll']")
    elif classify(clean[0]) != "system":
        problems.append("self-test: KERNEL32.dll was not classified as system")
    dirty = imported_dlls(build_minimal_pe("VCRUNTIME140_1.dll"))
    if dirty != ["VCRUNTIME140_1.dll"]:
        problems.append(f"self-test: parsed {dirty!r}, expected the CRT name")
    elif classify(dirty[0]) != "crt":
        problems.append("self-test: VCRUNTIME140_1.dll was not classified as crt")
    if classify("VCOMP140.DLL") != "crt":
        problems.append("self-test: VCOMP140.DLL (uppercase) was not classified as crt")
    if classify("SOMETHINGELSE.dll") != "unknown":
        problems.append("self-test: an unknown DLL passed the allowlist")
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", type=Path, help=".exe or .zip artifact")
    parser.add_argument("--zip", action="store_true", help="deprecated no-op (suffix decides)")
    parser.add_argument("--self-test", action="store_true", help="exercise the parser in memory")
    args = parser.parse_args(argv)

    failures: list[str] = []
    if args.self_test:
        problems = self_test()
        if problems:
            for problem in problems:
                print(f"self-test FAIL: {problem}")
            return 1
        print("self-test ok: parser, CRT detection and allowlist all behave")

    for path in args.paths:
        if not path.exists():
            failures.append(f"{path}: does not exist")
            continue
        failures += check_path(path)

    if not args.self_test and not args.paths:
        parser.error("give at least one artifact path, or --self-test")

    if failures:
        print("\nFAILED: this artifact will not start on a clean Windows install")
        for failure in dict.fromkeys(failures):
            print(f"  - {failure}")
        return 1
    if args.paths:
        print("\nok: every import is a Windows system DLL")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))