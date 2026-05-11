"""
pe_export_walker.py
-------------------
Manual PE export resolution for x86/x64 — mirrors exactly what Windows
loader and position-independent shellcode do.

Supports:
  - resolve_by_name()   — string match
  - resolve_by_hash()   — hash-based (avoids embedding strings; AV evasion)
  - forwarded export detection and recursive resolution
  - pluggable read primitives (swap in Frida, ctypes, pwnlib, raw bytes, etc.)

Tested against: kernel32.dll, ntdll.dll, kernelbase.dll on Windows 10/11
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

ReadDword = Callable[[int], int]  # addr -> DWORD
ReadWord = Callable[[int], int]  # addr -> WORD
ReadCStr = Callable[[int], bytes]  # addr -> null-terminated bytes


@dataclass
class ExportEntry:
    name: str
    ordinal: int  # biased ordinal (Base + index) — informational only
    ordinal_idx: int  # zero-based index into AddressOfFunctions
    func_rva: int  # raw RVA from AddressOfFunctions
    func_va: int  # module_base + func_rva
    forwarded: bool = False
    forward_str: str = ""  # e.g. "NTDLL.RtlAcquireSRWLockExclusive"


@dataclass
class ExportDirectory:
    base: int  # module base VA
    export_va: int  # IMAGE_EXPORT_DIRECTORY VA
    export_size: int
    ordinal_base: int  # Export.Base field
    num_functions: int  # NumberOfFunctions
    num_names: int  # NumberOfNames
    functions_va: int  # AddressOfFunctions table VA
    names_va: int  # AddressOfNames table VA
    name_ordinals_va: int  # AddressOfNameOrdinals table VA


# ---------------------------------------------------------------------------
# Read primitives — swap these out for your debugger's read functions
# ---------------------------------------------------------------------------


def make_bytes_reader(
    data: bytes, base_va: int
) -> tuple[ReadDword, ReadWord, ReadCStr]:
    """
    Build read primitives from a raw bytes buffer (e.g. bytes from
    open('kernel32.dll','rb').read(), mapped at base_va).

    For WinDbg / x64dbg / Frida usage, replace with debugger read calls.
    """

    def _offset(va: int) -> int:
        off = va - base_va
        if off < 0 or off >= len(data):
            raise ValueError(f"VA 0x{va:08x} out of range (base=0x{base_va:08x})")
        return off

    def rd(va: int) -> int:
        return struct.unpack_from("<I", data, _offset(va))[0]

    def rw(va: int) -> int:
        return struct.unpack_from("<H", data, _offset(va))[0]

    def rs(va: int) -> bytes:
        off = _offset(va)
        end = data.index(b"\x00", off)
        return data[off:end]

    return rd, rw, rs


# ---------------------------------------------------------------------------
# Hash functions
# ---------------------------------------------------------------------------


def ror32(val: int, bits: int) -> int:
    bits %= 32
    return ((val >> bits) | (val << (32 - bits))) & 0xFFFFFFFF


def hash_ror13_add(name: bytes) -> int:
    """
    Classic ROR-13-ADD hash used in most public shellcode (Metasploit, etc.).
    Case-sensitive on the raw export name bytes.
    """
    h = 0
    for b in name:
        h = ror32(h, 13)
        h = (h + b) & 0xFFFFFFFF
    return h


def hash_djb2(name: bytes) -> int:
    h = 5381
    for b in name:
        h = ((h << 5) + h + b) & 0xFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# PE parser
# ---------------------------------------------------------------------------


class PEExportWalker:
    """
    Walks PE export tables exactly as a Windows loader or shellcode would.

    Instantiate with three read primitives and the module base address.
    The read primitives must accept a VA and return the appropriate type.

    Example (raw file):
        data = open('C:/Windows/System32/kernel32.dll','rb').read()
        rd, rw, rs = make_bytes_reader(data, base_va=0x75680000)
        walker = PEExportWalker(rd, rw, rs, base=0x75680000)
        va = walker.resolve_by_name('WinExec')

    Example (Frida / ctypes — replace reads with your primitives):
        rd = lambda va: struct.unpack('<I', read_process_memory(va, 4))[0]
        rw = lambda va: struct.unpack('<H', read_process_memory(va, 2))[0]
        rs = lambda va: read_cstring_from_process(va)
        walker = PEExportWalker(rd, rw, rs, base=kernel32_base)
    """

    def __init__(
        self,
        read_dword: ReadDword,
        read_word: ReadWord,
        read_cstr: ReadCStr,
        base: int,
    ) -> None:
        self._rd = read_dword
        self._rw = read_word
        self._rs = read_cstr
        self._base = base
        self._exp: Optional[ExportDirectory] = None

    # ------------------------------------------------------------------
    # Internal: parse export directory once, cache it
    # ------------------------------------------------------------------

    def _get_export_dir(self) -> ExportDirectory:
        if self._exp is not None:
            return self._exp

        base = self._base

        # DOS header — MZ check + e_lfanew
        e_magic = self._rw(base + 0x00)
        if e_magic != 0x5A4D:
            raise ValueError(
                f"Not a valid PE: e_magic=0x{e_magic:04x} (expected 0x5A4D 'MZ')"
            )

        e_lfanew = self._rd(base + 0x3C)
        nt_hdrs = base + e_lfanew

        # NT headers — PE signature check
        sig = self._rd(nt_hdrs)
        if sig != 0x00004550:
            raise ValueError(f"Bad PE signature: 0x{sig:08x}")

        # IMAGE_OPTIONAL_HEADER starts at NT+0x18 (same for PE32 and PE32+)
        opt_hdr = nt_hdrs + 0x18

        # Magic: 0x010B = PE32, 0x020B = PE32+
        magic = self._rw(opt_hdr)
        if magic == 0x010B:  # PE32 (x86)
            export_dir_off = 0x60
        elif magic == 0x020B:  # PE32+ (x64)
            export_dir_off = 0x70
        else:
            raise ValueError(f"Unknown OptionalHeader magic: 0x{magic:04x}")

        export_rva = self._rd(opt_hdr + export_dir_off)
        export_size = self._rd(opt_hdr + export_dir_off + 4)
        export_va = base + export_rva

        # IMAGE_EXPORT_DIRECTORY fields
        ordinal_base = self._rd(export_va + 0x10)  # Base
        num_functions = self._rd(export_va + 0x14)  # NumberOfFunctions
        num_names = self._rd(export_va + 0x18)  # NumberOfNames
        funcs_rva = self._rd(export_va + 0x1C)  # AddressOfFunctions  (RVA)
        names_rva = self._rd(export_va + 0x20)  # AddressOfNames      (RVA)
        name_ords_rva = self._rd(export_va + 0x24)  # AddressOfNameOrdinals (RVA)

        self._exp = ExportDirectory(
            base=base,
            export_va=export_va,
            export_size=export_size,
            ordinal_base=ordinal_base,
            num_functions=num_functions,
            num_names=num_names,
            functions_va=base + funcs_rva,
            names_va=base + names_rva,
            name_ordinals_va=base + name_ords_rva,
        )
        return self._exp

    # ------------------------------------------------------------------
    # Internal: check for forwarded export
    #
    # A function RVA that falls inside the export directory's VA range
    # is NOT code — it's an ASCII forward string, e.g.:
    #   "NTDLL.RtlAcquireSRWLockExclusive"
    # ------------------------------------------------------------------

    def _is_forwarded(self, func_rva: int) -> bool:
        exp = self._get_export_dir()
        export_rva = exp.export_va - self._base
        return export_rva <= func_rva < export_rva + exp.export_size

    def _read_forward_str(self, func_rva: int) -> str:
        va = self._base + func_rva
        return self._rs(va).decode("ascii")

    # ------------------------------------------------------------------
    # Internal: resolve a single index into ExportEntry
    # ------------------------------------------------------------------

    def _entry_at(self, i: int) -> ExportEntry:
        exp = self._get_export_dir()

        name_rva = self._rd(exp.names_va + i * 4)
        name = self._rs(self._base + name_rva).decode("ascii")
        ordinal_idx = self._rw(exp.name_ordinals_va + i * 2)  # WORD, zero-based
        func_rva = self._rd(exp.functions_va + ordinal_idx * 4)
        func_va = self._base + func_rva
        forwarded = self._is_forwarded(func_rva)
        forward_str = self._read_forward_str(func_rva) if forwarded else ""

        return ExportEntry(
            name=name,
            ordinal=exp.ordinal_base + ordinal_idx,
            ordinal_idx=ordinal_idx,
            func_rva=func_rva,
            func_va=func_va,
            forwarded=forwarded,
            forward_str=forward_str,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve_by_name(self, target: str) -> Optional[ExportEntry]:
        """
        Linear scan of AddressOfNames for exact string match.
        Returns ExportEntry (may be forwarded — caller decides whether to follow).
        """
        exp = self._get_export_dir()
        for i in range(exp.num_names):
            entry = self._entry_at(i)
            if entry.name == target:
                return entry
        return None

    def resolve_by_hash(
        self,
        target_hash: int,
        hash_fn: Callable[[bytes], int] = hash_ror13_add,
    ) -> Optional[ExportEntry]:
        """
        Hash-based resolution — avoids embedding export name strings.
        Default hash: ROR-13-ADD (Metasploit / most public shellcode convention).

        Example:
            target = hash_ror13_add(b'WinExec')
            entry  = walker.resolve_by_hash(target)
        """
        exp = self._get_export_dir()
        for i in range(exp.num_names):
            entry = self._entry_at(i)
            if hash_fn(entry.name.encode()) == target_hash:
                return entry
        return None

    def dump_exports(self, *, include_forwarded: bool = True) -> list[ExportEntry]:
        """Return all named exports. Useful for auditing or generating hash tables."""
        exp = self._get_export_dir()
        results = []
        for i in range(exp.num_names):
            entry = self._entry_at(i)
            if not include_forwarded and entry.forwarded:
                continue
            results.append(entry)
        return results

    def export_dir_info(self) -> dict:
        """Return parsed export directory fields — mirrors WinDbg's !dh output."""
        exp = self._get_export_dir()
        return {
            "module_base": f"0x{exp.base:08x}",
            "export_dir_va": f"0x{exp.export_va:08x}",
            "export_dir_size": f"0x{exp.export_size:x}",
            "ordinal_base": exp.ordinal_base,
            "num_functions": exp.num_functions,
            "num_names": exp.num_names,
            "functions_table_va": f"0x{exp.functions_va:08x}",
            "names_table_va": f"0x{exp.names_va:08x}",
            "ordinals_table_va": f"0x{exp.name_ordinals_va:08x}",
        }


# ---------------------------------------------------------------------------
# Forwarded export resolver
#
# Follows the forward chain across modules.
# Requires a registry mapping module name (uppercase, no .dll) → PEExportWalker.
# ---------------------------------------------------------------------------


class ForwardResolver:
    """
    Resolves forwarded exports across loaded modules.

    Usage:
        registry = {
            'KERNEL32': PEExportWalker(rd_k32, rw_k32, rs_k32, base=0x75680000),
            'NTDLL':    PEExportWalker(rd_ntdll, rw_ntdll, rs_ntdll, base=0x77800000),
            'KERNELBASE': PEExportWalker(...),
        }
        resolver = ForwardResolver(registry)
        va = resolver.resolve('KERNEL32', 'AcquireSRWLockExclusive')
    """

    def __init__(self, registry: dict[str, PEExportWalker], max_depth: int = 8) -> None:
        self._reg = {k.upper(): v for k, v in registry.items()}
        self._max_depth = max_depth

    def resolve(
        self,
        module_name: str,
        export_name: str,
        _depth: int = 0,
    ) -> Optional[int]:
        """
        Returns callable VA or None.
        Follows forward chains up to max_depth hops.
        """
        if _depth > self._max_depth:
            raise RecursionError(f"Forward chain depth exceeded ({self._max_depth})")

        key = module_name.upper().removesuffix(".DLL")
        walker = self._reg.get(key)
        if walker is None:
            raise KeyError(f"Module not in registry: {module_name!r}")

        entry = walker.resolve_by_name(export_name)
        if entry is None:
            return None

        if not entry.forwarded:
            return entry.func_va

        # forward_str is "MODULE.FunctionName" or "MODULE.#Ordinal"
        mod_part, _, fn_part = entry.forward_str.partition(".")
        return self.resolve(mod_part, fn_part, _depth + 1)


# ---------------------------------------------------------------------------
# Utility: generate hash table for assembly / shellcode
# ---------------------------------------------------------------------------


def generate_hash_table(
    walker: PEExportWalker,
    targets: list[str],
    hash_fn: Callable[[bytes], int] = hash_ror13_add,
) -> dict[str, int]:
    """
    Generate the hash constants you'd embed in shellcode.

    Example output:
        {
            'WinExec':       0x98fe8a0e,
            'LoadLibraryA':  0xec0e4e8e,
            'GetProcAddress': 0x7c0dfcaa,
        }
    """
    result = {}
    for name in targets:
        result[name] = hash_fn(name.encode())
    return result


# ---------------------------------------------------------------------------
# Demo — works with raw DLL bytes (no debugger needed)
# ---------------------------------------------------------------------------


def demo_from_file(dll_path: str, base_va: int = 0x75680000) -> None:
    """
    Walk exports from a raw DLL file on disk.
    base_va should match the file's preferred ImageBase (or what you're
    simulating for the exercise).
    """
    with open(dll_path, "rb") as f:
        data = f.read()

    rd, rw, rs = make_bytes_reader(data, base_va)
    walker = PEExportWalker(rd, rw, rs, base=base_va)

    print("=== Export Directory ===")
    for k, v in walker.export_dir_info().items():
        print(f"  {k:<22} {v}")

    targets = ["WinExec", "LoadLibraryA", "GetProcAddress", "AcquireSRWLockExclusive"]
    print("\n=== Name Resolution ===")
    for name in targets:
        entry = walker.resolve_by_name(name)
        if entry is None:
            print(f"  {name:<30} NOT FOUND")
        elif entry.forwarded:
            print(f"  {name:<30} FORWARDED → {entry.forward_str}")
        else:
            print(
                f"  {name:<30} VA=0x{entry.func_va:08x}  RVA=0x{entry.func_rva:05x}  ord={entry.ordinal}"
            )

    print("\n=== Hash Table (ROR-13-ADD) ===")
    hashes = generate_hash_table(walker, targets)
    for name, h in hashes.items():
        print(f"  {name:<30} 0x{h:08x}")

    print("\n=== Hash Resolution Verify ===")
    for name, h in hashes.items():
        entry = walker.resolve_by_hash(h)
        if entry:
            print(f"  0x{h:08x} → {entry.name}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python pe_export_walker.py <path_to_dll> [base_va_hex]")
        print(
            "  Example: python pe_export_walker.py C:/Windows/System32/kernel32.dll 0x75680000"
        )
        sys.exit(1)
    path = sys.argv[1]
    base = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x75680000
    demo_from_file(path, base)
