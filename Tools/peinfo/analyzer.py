"""
Static PE analysis engine for exploit development.

Extracts PE header metadata, compile-time mitigations, sections, imports,
interesting strings, version resources, and gadget pre-enumeration from
a PE file on disk.  Everything here is static analysis -- no runtime or
debugger state is consulted.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pefile

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FileInfo:
    path: str
    size: int
    machine: str
    machine_raw: int
    subsystem: str
    subsystem_raw: int
    timestamp: str
    timestamp_raw: int
    linker_version: str
    checksum: int
    characteristics: int


@dataclass
class Mitigations:
    nx_compat: bool = False
    dynamic_base: bool = False
    high_entropy_va: bool = False
    force_integrity: bool = False
    no_seh: bool = False
    no_bind: bool = False
    app_container: bool = False
    guard_cf: bool = False
    terminal_server_aware: bool = False
    no_isolation: bool = False
    relocations_present: bool = False
    gs_cookie: Optional[bool] = None
    seh_table_present: Optional[bool] = None
    safeseh: Optional[bool] = None


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    entropy: float
    characteristics: int
    readable: bool
    writable: bool
    executable: bool


@dataclass
class ImportEntry:
    dll: str
    functions: list[str]


@dataclass
class CategorizedImports:
    exploitation: list[str] = field(default_factory=list)
    dangerous_crt: list[str] = field(default_factory=list)
    networking: list[str] = field(default_factory=list)
    registry: list[str] = field(default_factory=list)
    process: list[str] = field(default_factory=list)
    crypto: list[str] = field(default_factory=list)
    file_io: list[str] = field(default_factory=list)


@dataclass
class VersionInfo:
    company: str = ""
    product: str = ""
    version: str = ""
    description: str = ""
    copyright: str = ""
    original_filename: str = ""


@dataclass
class GadgetCounts:
    ret: int = 0
    pop_ret: int = 0
    pop_pop_ret: int = 0
    jmp_esp: int = 0
    call_esp: int = 0
    call_eax: int = 0
    call_ecx: int = 0
    call_edx: int = 0
    call_ebx: int = 0
    call_esi: int = 0
    call_edi: int = 0
    call_ebp: int = 0
    push_esp_ret: int = 0
    pushad_ret: int = 0
    xchg_eax_esp_ret: int = 0
    add_esp_ret: int = 0
    mov_esp_ret: int = 0


@dataclass
class ExploitabilitySummary:
    rop_candidate: bool = False
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class PEReport:
    file_info: FileInfo
    mitigations: Mitigations
    memory_layout: dict[str, int]
    sections: list[SectionInfo]
    imports: list[ImportEntry]
    categorized_imports: CategorizedImports
    interesting_strings: list[str]
    version_info: Optional[VersionInfo]
    gadget_counts: GadgetCounts
    exploitability: ExploitabilitySummary


# ---------------------------------------------------------------------------
# Import categorization tables
# ---------------------------------------------------------------------------

EXPLOITATION_APIS = {
    "VirtualProtect", "VirtualProtectEx",
    "VirtualAlloc", "VirtualAllocEx",
    "NtProtectVirtualMemory",
    "WriteProcessMemory", "NtWriteVirtualMemory",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress",
    "WinExec", "ShellExecuteA", "ShellExecuteW",
    "ShellExecuteExA", "ShellExecuteExW",
    "CreateProcessA", "CreateProcessW",
    "HeapCreate", "HeapAlloc", "HeapFree",
    "SetProcessDEPPolicy",
    "NtSetInformationProcess",
    "MapViewOfFile", "CreateFileMappingA", "CreateFileMappingW",
}

DANGEROUS_CRT = {
    "strcpy", "strncpy", "wcscpy", "wcsncpy",
    "strcat", "strncat", "wcscat", "wcsncat",
    "sprintf", "vsprintf", "swprintf",
    "gets", "_gets",
    "memcpy", "memmove", "wmemcpy",
    "scanf", "sscanf", "fscanf",
    "printf", "fprintf",
}

NETWORKING_APIS = {
    "recv", "recvfrom", "send", "sendto",
    "accept", "bind", "listen", "connect",
    "socket", "WSAStartup", "WSASocketA", "WSASocketW",
    "WSARecv", "WSASend", "WSAAccept", "WSAConnect",
    "InternetOpenA", "InternetOpenW",
    "InternetOpenUrlA", "InternetOpenUrlW",
    "HttpOpenRequestA", "HttpOpenRequestW",
    "HttpSendRequestA", "HttpSendRequestW",
    "URLDownloadToFileA", "URLDownloadToFileW",
}

REGISTRY_APIS = {
    "RegOpenKeyExA", "RegOpenKeyExW",
    "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW",
    "RegQueryValueExA", "RegQueryValueExW",
    "RegDeleteKeyA", "RegDeleteKeyW",
    "RegDeleteValueA", "RegDeleteValueW",
}

PROCESS_APIS = {
    "CreateThread", "CreateRemoteThread",
    "OpenProcess", "TerminateProcess",
    "VirtualAllocEx", "WriteProcessMemory",
    "CreateToolhelp32Snapshot",
    "NtQueryInformationProcess",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "OutputDebugStringA", "OutputDebugStringW",
}

CRYPTO_APIS = {
    "CryptAcquireContextA", "CryptAcquireContextW",
    "CryptEncrypt", "CryptDecrypt",
    "CryptCreateHash", "CryptHashData",
    "CryptDeriveKey", "CryptGenKey",
    "CryptImportKey", "CryptExportKey",
}

FILE_IO_APIS = {
    "CreateFileA", "CreateFileW",
    "ReadFile", "WriteFile",
    "SetFilePointer", "SetFilePointerEx",
    "DeleteFileA", "DeleteFileW",
    "CopyFileA", "CopyFileW",
    "MoveFileA", "MoveFileW",
}

INTERESTING_STRING_PATTERNS = [
    "http://", "https://", "ftp://",
    "cmd.exe", "cmd /c", "powershell",
    "calc.exe", "notepad.exe",
    "/bin/sh", "/bin/bash",
    "password", "passwd",
    "license", "serial", "registration",
    "admin", "root",
    "debug", "backdoor",
    ".dll", ".exe", ".bat", ".ps1",
    "AAAA",
]

# ---------------------------------------------------------------------------
# Machine / subsystem lookups
# ---------------------------------------------------------------------------

MACHINE_TYPES = {
    0x014C: "x86 (I386)",
    0x0200: "IA64",
    0x8664: "x64 (AMD64)",
    0x01C0: "ARM",
    0x01C4: "ARMv7 Thumb-2",
    0xAA64: "ARM64",
}

SUBSYSTEM_TYPES = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI (Console)",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows Boot Application",
}

# ---------------------------------------------------------------------------
# Byte patterns for gadget scanning (x86 only)
# ---------------------------------------------------------------------------

GADGET_PATTERNS: dict[str, list[bytes]] = {
    "ret": [b"\xc3"],
    "pop_ret": [
        bytes([0x58 + r, 0xc3]) for r in range(8)  # pop eax..edi; ret
    ],
    "pop_pop_ret": [
        bytes([0x58 + r1, 0x58 + r2, 0xc3])
        for r1 in range(8) for r2 in range(8)
    ],
    "jmp_esp": [b"\xff\xe4"],
    "call_esp": [b"\xff\xd4"],
    "call_eax": [b"\xff\xd0"],
    "call_ecx": [b"\xff\xd1"],
    "call_edx": [b"\xff\xd2"],
    "call_ebx": [b"\xff\xd3"],
    "call_esi": [b"\xff\xd6"],
    "call_edi": [b"\xff\xd7"],
    "call_ebp": [b"\xff\xd5"],
    "push_esp_ret": [b"\x54\xc3"],
    "pushad_ret": [b"\x60\xc3"],
    "xchg_eax_esp_ret": [b"\x94\xc3"],
}


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class PEAnalyzer:
    """Analyze a PE file and produce a structured report."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.pe = pefile.PE(str(self.path), fast_load=False)

    def close(self) -> None:
        self.pe.close()

    def __enter__(self) -> PEAnalyzer:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- public API --

    def analyze(self) -> PEReport:
        return PEReport(
            file_info=self._file_info(),
            mitigations=self._mitigations(),
            memory_layout=self._memory_layout(),
            sections=self._sections(),
            imports=self._imports(),
            categorized_imports=self._categorize_imports(),
            interesting_strings=self._interesting_strings(),
            version_info=self._version_info(),
            gadget_counts=self._gadget_counts(),
            exploitability=self._exploitability(),
        )

    # -- private helpers --

    def _file_info(self) -> FileInfo:
        pe = self.pe
        oh = pe.OPTIONAL_HEADER
        ts_raw = pe.FILE_HEADER.TimeDateStamp
        import datetime
        try:
            ts = datetime.datetime.fromtimestamp(
                ts_raw, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, ValueError):
            ts = f"0x{ts_raw:08X}"

        machine_raw = pe.FILE_HEADER.Machine
        machine = MACHINE_TYPES.get(machine_raw, f"0x{machine_raw:04X}")

        sub_raw = oh.Subsystem
        subsystem = SUBSYSTEM_TYPES.get(sub_raw, f"0x{sub_raw:04X}")

        return FileInfo(
            path=str(self.path),
            size=self.path.stat().st_size,
            machine=machine,
            machine_raw=machine_raw,
            subsystem=subsystem,
            subsystem_raw=sub_raw,
            timestamp=ts,
            timestamp_raw=ts_raw,
            linker_version=f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
            checksum=oh.CheckSum,
            characteristics=pe.FILE_HEADER.Characteristics,
        )

    def _mitigations(self) -> Mitigations:
        pe = self.pe
        dc = pe.OPTIONAL_HEADER.DllCharacteristics

        has_reloc_section = any(
            s.Name.rstrip(b"\x00").decode("ascii", errors="replace") == ".reloc"
            for s in pe.sections
        )
        has_reloc_dir = (
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]
            ].Size > 0
        )
        relocs = has_reloc_section or has_reloc_dir

        gs = self._detect_gs_cookie()

        safeseh = self._detect_safeseh()
        seh_table = None
        if safeseh is not None:
            seh_table = safeseh

        return Mitigations(
            nx_compat=bool(dc & 0x0100),
            dynamic_base=bool(dc & 0x0040),
            high_entropy_va=bool(dc & 0x0020),
            force_integrity=bool(dc & 0x0080),
            no_seh=bool(dc & 0x0400),
            no_bind=bool(dc & 0x0800),
            app_container=bool(dc & 0x1000),
            guard_cf=bool(dc & 0x4000),
            terminal_server_aware=bool(dc & 0x8000),
            no_isolation=bool(dc & 0x0200),
            relocations_present=relocs,
            gs_cookie=gs,
            seh_table_present=seh_table,
            safeseh=safeseh,
        )

    def _detect_gs_cookie(self) -> Optional[bool]:
        all_imports = self._all_import_names()
        if "__security_check_cookie" in all_imports:
            return True
        if "__security_cookie" in all_imports:
            return True
        cookie_ref = b"__security_cookie"
        data = self.pe.get_memory_mapped_image()
        if cookie_ref in data:
            return True
        return False

    def _detect_safeseh(self) -> Optional[bool]:
        pe = self.pe
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400:
            return None

        load_config_idx = pefile.DIRECTORY_ENTRY[
            "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"
        ]
        lc_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[load_config_idx]
        if lc_dir.VirtualAddress == 0 or lc_dir.Size == 0:
            return False

        if not hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
            pe.parse_data_directories(
                directories=[load_config_idx]
            )

        if not hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
            return False

        lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct

        seh_table_va = getattr(lc, "SEHandlerTable", 0)
        seh_count = getattr(lc, "SEHandlerCount", 0)

        if seh_table_va and seh_count > 0:
            return True
        return False

    def _memory_layout(self) -> dict[str, int]:
        oh = self.pe.OPTIONAL_HEADER
        return {
            "image_base": oh.ImageBase,
            "entry_point": oh.ImageBase + oh.AddressOfEntryPoint,
            "section_alignment": oh.SectionAlignment,
            "file_alignment": oh.FileAlignment,
            "image_size": oh.SizeOfImage,
            "header_size": oh.SizeOfHeaders,
            "stack_reserve": oh.SizeOfStackReserve,
            "stack_commit": oh.SizeOfStackCommit,
            "heap_reserve": oh.SizeOfHeapReserve,
            "heap_commit": oh.SizeOfHeapCommit,
        }

    def _sections(self) -> list[SectionInfo]:
        result = []
        for s in self.pe.sections:
            name = s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            chars = s.Characteristics
            result.append(SectionInfo(
                name=name,
                virtual_address=s.VirtualAddress,
                virtual_size=s.Misc_VirtualSize,
                raw_offset=s.PointerToRawData,
                raw_size=s.SizeOfRawData,
                entropy=round(s.get_entropy(), 2),
                characteristics=chars,
                readable=bool(chars & 0x40000000),
                writable=bool(chars & 0x80000000),
                executable=bool(chars & 0x20000000),
            ))
        return result

    def _imports(self) -> list[ImportEntry]:
        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return []
        result = []
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("ascii", errors="replace"))
                elif imp.ordinal is not None:
                    funcs.append(f"ordinal#{imp.ordinal}")
            result.append(ImportEntry(dll=dll, functions=funcs))
        return result

    def _all_import_names(self) -> set[str]:
        names: set[str] = set()
        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return names
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    names.add(imp.name.decode("ascii", errors="replace"))
        return names

    def _categorize_imports(self) -> CategorizedImports:
        all_names = self._all_import_names()
        return CategorizedImports(
            exploitation=sorted(all_names & EXPLOITATION_APIS),
            dangerous_crt=sorted(all_names & DANGEROUS_CRT),
            networking=sorted(all_names & NETWORKING_APIS),
            registry=sorted(all_names & REGISTRY_APIS),
            process=sorted(all_names & PROCESS_APIS),
            crypto=sorted(all_names & CRYPTO_APIS),
            file_io=sorted(all_names & FILE_IO_APIS),
        )

    def _interesting_strings(self) -> list[str]:
        data = bytes(self.pe.__data__)
        found: list[str] = []
        ascii_strings = self._extract_strings(data, min_len=4)
        for s in ascii_strings:
            sl = s.lower()
            for pattern in INTERESTING_STRING_PATTERNS:
                if pattern.lower() in sl:
                    found.append(s)
                    break
        seen: set[str] = set()
        deduped: list[str] = []
        for s in found:
            if s not in seen:
                seen.add(s)
                deduped.append(s)
        return deduped[:200]

    @staticmethod
    def _extract_strings(data: bytes, min_len: int = 4) -> list[str]:
        result: list[str] = []
        current: list[int] = []
        for b in data:
            if 0x20 <= b < 0x7F:
                current.append(b)
            else:
                if len(current) >= min_len:
                    result.append(bytes(current).decode("ascii"))
                current = []
        if len(current) >= min_len:
            result.append(bytes(current).decode("ascii"))
        return result

    def _version_info(self) -> Optional[VersionInfo]:
        pe = self.pe
        if not hasattr(pe, "VS_VERSIONINFO"):
            if not hasattr(pe, "FileInfo"):
                return None

        vi = VersionInfo()
        key_map = {
            b"CompanyName": "company",
            b"ProductName": "product",
            b"FileVersion": "version",
            b"ProductVersion": "version",
            b"FileDescription": "description",
            b"LegalCopyright": "copyright",
            b"OriginalFilename": "original_filename",
        }

        if hasattr(pe, "FileInfo"):
            for fi_list in pe.FileInfo:
                for fi in fi_list:
                    if hasattr(fi, "StringTable"):
                        for st in fi.StringTable:
                            for k, v in st.entries.items():
                                attr = key_map.get(k)
                                if attr and v:
                                    val = v.decode(
                                        "utf-8", errors="replace"
                                    ).strip()
                                    if val and not getattr(vi, attr):
                                        setattr(vi, attr, val)

        if any([vi.company, vi.product, vi.version,
                vi.description, vi.copyright]):
            return vi
        return None

    def _gadget_counts(self) -> GadgetCounts:
        if self.pe.FILE_HEADER.Machine != 0x014C:
            return GadgetCounts()

        exec_data = bytearray()
        for s in self.pe.sections:
            if s.Characteristics & 0x20000000:
                raw = s.get_data()
                exec_data.extend(raw)

        if not exec_data:
            return GadgetCounts()

        exec_bytes = bytes(exec_data)
        counts = GadgetCounts()

        for name, patterns in GADGET_PATTERNS.items():
            total = 0
            for pat in patterns:
                total += _count_pattern(exec_bytes, pat)
            setattr(counts, name, total)

        counts.add_esp_ret = _count_add_esp_ret(exec_bytes)

        return counts

    def _exploitability(self) -> ExploitabilitySummary:
        mit = self._mitigations()
        gadgets = self._gadget_counts()
        cat = self._categorize_imports()
        layout = self._memory_layout()

        reasons: list[str] = []
        warnings: list[str] = []

        fixed_base = not mit.dynamic_base
        if fixed_base:
            reasons.append("Fixed image base (no ASLR/DYNAMIC_BASE)")
        if not mit.nx_compat:
            reasons.append("NX_COMPAT absent")
        if not mit.relocations_present:
            reasons.append("No relocations (.reloc missing)")
        if mit.safeseh is False:
            reasons.append("No SafeSEH")
        elif mit.no_seh:
            reasons.append("NO_SEH set (no SEH handlers)")
        if not mit.guard_cf:
            reasons.append("No CFG")
        if mit.gs_cookie is False:
            reasons.append("No GS security cookie")

        if gadgets.ret > 50:
            reasons.append(f"{gadgets.ret} RET gadgets")
        if gadgets.jmp_esp > 0:
            reasons.append(f"{gadgets.jmp_esp} JMP ESP gadgets")
        if gadgets.push_esp_ret > 0:
            reasons.append(f"{gadgets.push_esp_ret} PUSH ESP; RET gadgets")

        vp_present = "VirtualProtect" in cat.exploitation or \
                     "VirtualProtectEx" in cat.exploitation
        va_present = "VirtualAlloc" in cat.exploitation or \
                     "VirtualAllocEx" in cat.exploitation
        if vp_present:
            reasons.append("Imports VirtualProtect")
        if va_present:
            reasons.append("Imports VirtualAlloc")

        if mit.gs_cookie:
            warnings.append("GS security cookie detected")
        if mit.safeseh:
            warnings.append("SafeSEH table present")
        if mit.nx_compat:
            warnings.append("NX_COMPAT set")
        if mit.dynamic_base:
            warnings.append("DYNAMIC_BASE set")
        if mit.guard_cf:
            warnings.append("CFG enabled")

        score = 0
        if fixed_base:
            score += 3
        if not mit.nx_compat:
            score += 2
        if not mit.relocations_present:
            score += 2
        if mit.safeseh is False:
            score += 2
        if mit.gs_cookie is False:
            score += 1
        if not mit.guard_cf:
            score += 1
        if gadgets.ret > 50:
            score += 1
        if gadgets.jmp_esp > 0:
            score += 2
        if vp_present or va_present:
            score += 1

        return ExploitabilitySummary(
            rop_candidate=score >= 6,
            reasons=reasons,
            warnings=warnings,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_pattern(data: bytes, pattern: bytes) -> int:
    count = 0
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        count += 1
        start = idx + 1
    return count


def _count_add_esp_ret(data: bytes) -> int:
    count = 0
    start = 0
    while True:
        idx = data.find(b"\x83\xc4", start)
        if idx == -1:
            break
        if idx + 3 < len(data) and data[idx + 3] == 0xc3:
            count += 1
        start = idx + 1
    idx2 = 0
    while True:
        idx2 = data.find(b"\x81\xc4", idx2)
        if idx2 == -1:
            break
        if idx2 + 6 < len(data) and data[idx2 + 6] == 0xc3:
            count += 1
        idx2 += 1
    return count
