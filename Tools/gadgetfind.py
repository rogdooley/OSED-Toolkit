#!/usr/bin/env python3
"""
gadgetfind.py - WinDbg (PyKD) live-process gadget finder for Win32 x86.

Run inside WinDbg after PyKD is available:
    !py C:\\Tools\\osed-toolkit\\gadgets\\gadgetfind.py --modules all --pattern "pop r32; pop r32; ret" --badchars "00 0a 0d"

Multi-module examples:
    !py ...\\gadgetfind.py --modules libpal,libeay32 --pattern "xchg eax, esp; ret"
    !py ...\\gadgetfind.py --modules all --exclude ntdll,kernel32 --pattern "add esp, imm8; ret" --imm8 0x10,0x1c,0x20,0x24,0x28

Notes:
- Scans *loaded module memory* (live debuggee).
- Byte-matches candidates then validates by disassembly via `u`.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from typing import Iterator, List, Optional, Sequence, Tuple

import pykd  # type: ignore

# -------------------------
# Models
# -------------------------


@dataclass(frozen=True)
class ModuleRange:
    name: str
    base: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.base


@dataclass(frozen=True)
class GadgetHit:
    address: int
    module: str
    pattern: str
    bytes_hex: str
    disasm: List[str]


# -------------------------
# x86 opcode knowledge
# -------------------------

POP_R32: dict[str, int] = {
    "eax": 0x58,
    "ecx": 0x59,
    "edx": 0x5A,
    "ebx": 0x5B,
    "esp": 0x5C,
    "ebp": 0x5D,
    "esi": 0x5E,
    "edi": 0x5F,
}

PUSH_R32: dict[str, int] = {
    "eax": 0x50,
    "ecx": 0x51,
    "edx": 0x52,
    "ebx": 0x53,
    "esp": 0x54,
    "ebp": 0x55,
    "esi": 0x56,
    "edi": 0x57,
}

RET: bytes = b"\xc3"

# Control transfer
JMP_R32: dict[str, bytes] = {
    # FF /4: JMP r/m32
    "eax": b"\xff\xe0",
    "ecx": b"\xff\xe1",
    "edx": b"\xff\xe2",
    "ebx": b"\xff\xe3",
    "esp": b"\xff\xe4",
    "ebp": b"\xff\xe5",
    "esi": b"\xff\xe6",
    "edi": b"\xff\xe7",
}
CALL_R32: dict[str, bytes] = {
    # FF /2: CALL r/m32
    "eax": b"\xff\xd0",
    "ecx": b"\xff\xd1",
    "edx": b"\xff\xd2",
    "ebx": b"\xff\xd3",
    "esp": b"\xff\xd4",
    "ebp": b"\xff\xd5",
    "esi": b"\xff\xd6",
    "edi": b"\xff\xd7",
}

# Pivots / stack adjust
XCHG_EAX_ESP: bytes = b"\x94"  # xchg eax, esp
MOV_ESP_EAX: bytes = b"\x89\xc4"  # mov esp, eax
ADD_ESP_IMM8_PREFIX: bytes = b"\x83\xc4"  # add esp, imm8
ADD_ESP_IMM32_PREFIX: bytes = b"\x81\xc4"  # add esp, imm32


# -------------------------
# Helpers
# -------------------------


def dbg(cmd: str) -> str:
    return pykd.dbgCommand(cmd)


def parse_badchars(s: str) -> set[int]:
    s = s.strip()
    if not s:
        return set()
    s = s.replace(",", " ").replace("\\x", " ")
    parts = [p for p in s.split() if p]
    out: set[int] = set()
    for p in parts:
        if not re.fullmatch(r"[0-9a-fA-F]{2}", p):
            raise ValueError(f"Invalid badchar byte: {p!r}")
        out.add(int(p, 16))
    return out


def parse_hex_int_list(s: str) -> List[int]:
    """
    Accepts: "0x10,0x1c,32" or "16 28 32"
    """
    s = s.strip()
    if not s:
        return []
    s = s.replace(",", " ")
    vals: List[int] = []
    for part in [p for p in s.split() if p]:
        base = 16 if part.lower().startswith("0x") else 10
        vals.append(int(part, base))
    return vals


def addr_has_badchars(addr: int, badchars: set[int]) -> bool:
    b0 = addr & 0xFF
    b1 = (addr >> 8) & 0xFF
    b2 = (addr >> 16) & 0xFF
    b3 = (addr >> 24) & 0xFF
    return any(b in badchars for b in (b0, b1, b2, b3))


def u_lines(addr: int, count: int) -> List[str]:
    out = dbg(f"u {addr:#x} L{count}")
    return [ln.rstrip() for ln in out.splitlines() if ln.strip()]


def list_loaded_modules() -> List[ModuleRange]:
    """
    Parse `lm` output. We keep it simple:
    - Find lines like: start end module
    - Ignore symbol noise
    """
    out = dbg("lm")
    mods: List[ModuleRange] = []
    for ln in out.splitlines():
        # e.g. "10000000 10052000   libpal"
        m = re.match(r"^\s*([0-9a-f`]+)\s+([0-9a-f`]+)\s+(\S+)\s*$", ln, flags=re.I)
        if not m:
            continue
        base = int(m.group(1).replace("`", ""), 16)
        end = int(m.group(2).replace("`", ""), 16)
        name = m.group(3)
        if end > base:
            mods.append(ModuleRange(name=name, base=base, end=end))
    return mods


def resolve_modules(selection: str, exclude_csv: str) -> List[ModuleRange]:
    """
    selection:
      - "all"
      - "name1,name2"
    exclude_csv:
      - "ntdll,kernel32"
    """
    exclude = {x.strip().lower() for x in exclude_csv.split(",") if x.strip()}
    all_mods = list_loaded_modules()

    if selection.strip().lower() == "all":
        mods = all_mods
    else:
        wanted = {x.strip().lower() for x in selection.split(",") if x.strip()}
        mods = [
            m
            for m in all_mods
            if m.name.lower() in wanted or (m.name.lower() + ".dll") in wanted
        ]

    # Apply exclude
    mods = [
        m
        for m in mods
        if m.name.lower() not in exclude and (m.name.lower() + ".dll") not in exclude
    ]
    return mods


def load_module_bytes(r: ModuleRange) -> bytes:
    data = pykd.loadBytes(r.base, r.size)  # type: ignore[attr-defined]
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    return bytes(int(x) & 0xFF for x in data)


def find_all(haystack: bytes, needle: bytes) -> Iterator[int]:
    if not needle:
        return
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            return
        yield idx
        start = idx + 1


def normalize_pattern(p: str) -> str:
    p = p.strip().lower()
    p = p.replace("\t", " ")
    p = re.sub(r"\s+", " ", p)
    p = p.replace(" ;", ";").replace("; ", ";")
    return p


# -------------------------
# Pattern expansion (small DSL)
# -------------------------


def pattern_to_byte_sequences(
    pattern: str,
    imm8_values: Sequence[int],
    imm32_values: Sequence[int],
) -> List[Tuple[str, bytes]]:
    """
    Supported instructions:
      - pop r32 | pop eax|ecx|...
      - push r32 | push eax|...
      - ret
      - jmp r32
      - call r32
      - xchg eax, esp
      - mov esp, eax
      - add esp, imm8
      - add esp, imm32
    """
    pat = normalize_pattern(pattern)
    ins = [x.strip() for x in pat.split(";") if x.strip()]
    if not ins:
        raise ValueError("Empty pattern")

    expanded: List[List[Tuple[str, bytes]]] = []

    for i in ins:
        if i == "ret":
            expanded.append([("ret", RET)])

        elif i.startswith("pop "):
            reg = i[4:].strip()
            if reg == "r32":
                expanded.append(
                    [(f"pop {r}", bytes([op])) for r, op in POP_R32.items()]
                )
            elif reg in POP_R32:
                expanded.append([(f"pop {reg}", bytes([POP_R32[reg]]))])
            else:
                raise ValueError(f"Unsupported register in pattern: {reg!r}")

        elif i.startswith("push "):
            reg = i[5:].strip()
            if reg == "r32":
                expanded.append(
                    [(f"push {r}", bytes([op])) for r, op in PUSH_R32.items()]
                )
            elif reg in PUSH_R32:
                expanded.append([(f"push {reg}", bytes([PUSH_R32[reg]]))])
            else:
                raise ValueError(f"Unsupported register in pattern: {reg!r}")

        elif i.startswith("jmp "):
            reg = i[4:].strip()
            if reg == "r32":
                expanded.append([(f"jmp {r}", bts) for r, bts in JMP_R32.items()])
            elif reg in JMP_R32:
                expanded.append([(f"jmp {reg}", JMP_R32[reg])])
            else:
                raise ValueError(f"Unsupported register in pattern: {reg!r}")

        elif i.startswith("call "):
            reg = i[5:].strip()
            if reg == "r32":
                expanded.append([(f"call {r}", bts) for r, bts in CALL_R32.items()])
            elif reg in CALL_R32:
                expanded.append([(f"call {reg}", CALL_R32[reg])])
            else:
                raise ValueError(f"Unsupported register in pattern: {reg!r}")

        elif i == "xchg eax, esp":
            expanded.append([("xchg eax, esp", XCHG_EAX_ESP)])

        elif i == "mov esp, eax":
            expanded.append([("mov esp, eax", MOV_ESP_EAX)])

        elif i == "add esp, imm8":
            if not imm8_values:
                raise ValueError("Pattern uses imm8 but --imm8 was empty.")
            choices = []
            for v in imm8_values:
                if not (0 <= v <= 0xFF):
                    raise ValueError(f"imm8 out of range: {v}")
                choices.append(
                    (f"add esp, 0x{v:02x}", ADD_ESP_IMM8_PREFIX + bytes([v]))
                )
            expanded.append(choices)

        elif i == "add esp, imm32":
            if not imm32_values:
                raise ValueError("Pattern uses imm32 but --imm32 was empty.")
            choices = []
            for v in imm32_values:
                if not (0 <= v <= 0xFFFFFFFF):
                    raise ValueError(f"imm32 out of range: {v}")
                # little-endian imm32
                imm = bytes(
                    [
                        (v >> 0) & 0xFF,
                        (v >> 8) & 0xFF,
                        (v >> 16) & 0xFF,
                        (v >> 24) & 0xFF,
                    ]
                )
                choices.append((f"add esp, 0x{v:08x}", ADD_ESP_IMM32_PREFIX + imm))
            expanded.append(choices)

        else:
            raise ValueError(f"Unsupported instruction in pattern: {i!r}")

    # Cartesian product of instruction expansions
    seqs: List[Tuple[str, bytes]] = [("", b"")]
    for choices in expanded:
        new: List[Tuple[str, bytes]] = []
        for acc_text, acc_bytes in seqs:
            for t, bts in choices:
                nt = f"{acc_text}; {t}" if acc_text else t
                nb = acc_bytes + bts
                new.append((nt, nb))
        seqs = new

    return seqs


# -------------------------
# Scanner
# -------------------------


def scan_one_module(
    module: ModuleRange,
    pattern: str,
    badchars: set[int],
    imm8_values: Sequence[int],
    imm32_values: Sequence[int],
    disasm_len: int,
    max_hits: int,
) -> List[GadgetHit]:
    module_bytes = load_module_bytes(module)
    seqs = pattern_to_byte_sequences(
        pattern, imm8_values=imm8_values, imm32_values=imm32_values
    )

    hits: List[GadgetHit] = []
    found = 0

    for rendered, needle in seqs:
        for off in find_all(module_bytes, needle):
            found += 1
            if found > max_hits:
                return hits

            addr = module.base + off
            if badchars and addr_has_badchars(addr, badchars):
                continue

            dis = u_lines(addr, disasm_len)
            if not dis:
                continue

            hits.append(
                GadgetHit(
                    address=addr,
                    module=module.name,
                    pattern=rendered,
                    bytes_hex=" ".join(f"{b:02x}" for b in needle),
                    disasm=dis,
                )
            )
    return hits


def build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Live WinDbg (PyKD) gadget finder for loaded modules (Win32 x86)."
    )
    ap.add_argument(
        "--modules",
        required=True,
        help='Module selection: "all" or "libpal,kernel32,..."',
    )
    ap.add_argument(
        "--exclude",
        default="",
        help='Comma list of modules to skip, e.g. "ntdll,kernel32"',
    )
    ap.add_argument(
        "--pattern",
        required=True,
        help='Pattern e.g. "pop r32; pop r32; ret" or "xchg eax, esp; ret"',
    )

    ap.add_argument(
        "--badchars", default="", help='Bad bytes e.g. "00 0a 0d" or "\\x00\\x0a\\x0d"'
    )
    ap.add_argument(
        "--imm8", default="", help='For patterns using imm8: e.g. "0x10,0x1c,0x20,0x24"'
    )
    ap.add_argument(
        "--imm32",
        default="",
        help='For patterns using imm32: e.g. "0x00000100,0x00000200"',
    )

    ap.add_argument(
        "--disasm-len",
        type=int,
        default=4,
        help="How many instructions to disassemble for validation",
    )
    ap.add_argument(
        "--max-hits",
        type=int,
        default=20000,
        help="Safety cap per module to avoid runaway output",
    )
    ap.add_argument(
        "--json", dest="json_out", default="", help="Write results to JSON path on disk"
    )
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_argparser().parse_args(argv)

    bad = parse_badchars(args.badchars) if args.badchars else set()
    imm8_values = parse_hex_int_list(args.imm8)
    imm32_values = parse_hex_int_list(args.imm32)

    mods = resolve_modules(args.modules, args.exclude)
    if not mods:
        print(
            f"[-] No modules resolved for selection={args.modules!r} exclude={args.exclude!r}"
        )
        return 2

    print(f"[+] Modules: {len(mods)}")
    print(f"[+] Pattern: {args.pattern}")
    if bad:
        print(
            f"[+] Badchars (address bytes): {', '.join(f'{b:02x}' for b in sorted(bad))}"
        )
    if imm8_values:
        print(f"[+] imm8 candidates: {', '.join(hex(v) for v in imm8_values)}")
    if imm32_values:
        print(f"[+] imm32 candidates: {', '.join(hex(v) for v in imm32_values)}")

    all_hits: List[GadgetHit] = []
    for m in mods:
        try:
            print(
                f"\n[=] Scanning {m.name} base={m.base:#x} end={m.end:#x} size={m.size:#x}"
            )
            hits = scan_one_module(
                m,
                pattern=args.pattern,
                badchars=bad,
                imm8_values=imm8_values,
                imm32_values=imm32_values,
                disasm_len=args.disasm_len,
                max_hits=args.max_hits,
            )
            print(f"[+] Hits in {m.name}: {len(hits)}")
            for h in hits[:200]:  # keep console sane
                print(f"\n{h.address:#x}  [{h.module}]  {h.pattern}  ({h.bytes_hex})")
                for ln in h.disasm:
                    print(f"  {ln}")
            if len(hits) > 200:
                print(
                    f"[!] Truncated console output for {m.name} (showing first 200). Use --json for full output."
                )
            all_hits.extend(hits)
        except Exception as e:
            print(f"[-] Failed scanning {m.name}: {e}")

    print(f"\n[+] Total hits: {len(all_hits)}")

    if args.json_out:
        payload = [
            {
                "address": hex(h.address),
                "module": h.module,
                "pattern": h.pattern,
                "bytes": h.bytes_hex,
                "disasm": h.disasm,
            }
            for h in all_hits
        ]
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"[+] Wrote JSON: {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
