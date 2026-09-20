#!/usr/bin/env python3
"""Verify mitigation flags and intentional primitives in built x86 PE files."""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_RELOCS_STRIPPED = 0x0001
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Section:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


class PEFile:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        if self.data[:2] != b"MZ":
            raise VerificationError(f"{path}: missing DOS signature")
        self.pe_offset = self.u32(0x3C)
        if self.data[self.pe_offset : self.pe_offset + 4] != b"PE\0\0":
            raise VerificationError(f"{path}: missing PE signature")

        coff = self.pe_offset + 4
        self.machine = self.u16(coff)
        self.section_count = self.u16(coff + 2)
        self.optional_size = self.u16(coff + 16)
        self.file_characteristics = self.u16(coff + 18)
        self.optional_offset = coff + 20
        if self.u16(self.optional_offset) != 0x10B:
            raise VerificationError(f"{path}: expected a PE32 optional header")

        self.image_base = self.u32(self.optional_offset + 28)
        self.dll_characteristics = self.u16(self.optional_offset + 70)
        directory_count = self.u32(self.optional_offset + 92)
        self.directories: list[tuple[int, int]] = []
        for index in range(min(directory_count, 16)):
            entry = self.optional_offset + 96 + (index * 8)
            self.directories.append((self.u32(entry), self.u32(entry + 4)))

        section_offset = self.optional_offset + self.optional_size
        self.sections: list[Section] = []
        for index in range(self.section_count):
            entry = section_offset + (index * 40)
            self.sections.append(
                Section(
                    virtual_size=self.u32(entry + 8),
                    virtual_address=self.u32(entry + 12),
                    raw_size=self.u32(entry + 16),
                    raw_offset=self.u32(entry + 20),
                    characteristics=self.u32(entry + 36),
                )
            )

    def u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]

    def rva_offset(self, rva: int) -> int:
        for section in self.sections:
            size = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + size:
                return section.raw_offset + (rva - section.virtual_address)
        raise VerificationError(f"{self.path}: RVA 0x{rva:08X} is not mapped")

    def c_string(self, offset: int) -> str:
        end = self.data.find(b"\0", offset)
        if end < 0:
            raise VerificationError(f"{self.path}: unterminated PE string")
        return self.data[offset:end].decode("ascii", errors="strict")

    @staticmethod
    def normalize_export(name: str) -> str:
        normalized = name[1:] if name.startswith("_") else name
        return normalized.split("@", 1)[0]

    def exports(self) -> dict[str, int]:
        if not self.directories or self.directories[0][0] == 0:
            return {}
        export_offset = self.rva_offset(self.directories[0][0])
        function_count = self.u32(export_offset + 20)
        name_count = self.u32(export_offset + 24)
        functions = self.rva_offset(self.u32(export_offset + 28))
        names = self.rva_offset(self.u32(export_offset + 32))
        ordinals = self.rva_offset(self.u32(export_offset + 36))

        result: dict[str, int] = {}
        for index in range(name_count):
            name_rva = self.u32(names + (index * 4))
            name = self.normalize_export(self.c_string(self.rva_offset(name_rva)))
            ordinal = self.u16(ordinals + (index * 2))
            if ordinal >= function_count:
                raise VerificationError(f"{self.path}: invalid export ordinal")
            result[name] = self.u32(functions + (ordinal * 4))
        return result

    def bytes_at_export(self, name: str, size: int) -> bytes:
        exports = self.exports()
        if name not in exports:
            raise VerificationError(f"{self.path}: missing export {name}")
        offset = self.rva_offset(exports[name])
        return self.data[offset : offset + size]

    def dynamic_base(self) -> bool:
        return bool(self.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)

    def nx_compatible(self) -> bool:
        return bool(self.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)

    def relocations_stripped(self) -> bool:
        return bool(self.file_characteristics & IMAGE_FILE_RELOCS_STRIPPED)

    def safe_seh_enabled(self) -> bool:
        if len(self.directories) <= 10 or self.directories[10][0] == 0:
            return False
        load_config_rva, load_config_size = self.directories[10]
        if load_config_size < 72:
            return False
        offset = self.rva_offset(load_config_rva)
        structure_size = self.u32(offset)
        if structure_size < 72:
            return False
        return self.u32(offset + 64) != 0 and self.u32(offset + 68) != 0

    def executable_contains(self, pattern: bytes) -> bool:
        for section in self.sections:
            if not section.characteristics & 0x20000000:
                continue
            start = section.raw_offset
            end = start + section.raw_size
            if pattern in self.data[start:end]:
                return True
        return False


SEQUENCES = {
    "helper_sequence_01": bytes.fromhex("FF E4"),
    "helper_sequence_02": bytes.fromhex("58 C3"),
    "helper_sequence_03": bytes.fromhex("59 C3"),
    "helper_sequence_04": bytes.fromhex("5A C3"),
    "helper_sequence_05": bytes.fromhex("5B C3"),
    "helper_sequence_06": bytes.fromhex("5D C3"),
    "helper_sequence_07": bytes.fromhex("5E C3"),
    "helper_sequence_08": bytes.fromhex("5F C3"),
    "helper_sequence_09": bytes.fromhex("F7 D8 C3"),
    "helper_sequence_10": bytes.fromhex("93 C3"),
    "helper_sequence_11": bytes.fromhex("60 C3"),
    "helper_sequence_12": bytes.fromhex("C3"),
    "helper_sequence_13": bytes.fromhex("58 5B C3"),
    "helper_sequence_14": bytes.fromhex("94 C3"),
    "helper_sequence_15": bytes.fromhex("8B 00 C3"),
    "helper_sequence_16": bytes.fromhex("96 C3"),
    "helper_sequence_17": bytes.fromhex("89 06 C3"),
    "helper_sequence_18": bytes.fromhex("83 C4 10 C3"),
    "helper_sequence_19": bytes.fromhex("FF D0 C3"),
    "helper_sequence_20": bytes.fromhex("FF E0"),
    "helper_sequence_21": bytes.fromhex("FF D4 C3"),
    "helper_sequence_22": bytes.fromhex("54 C3"),
}

ROP_SEQUENCES = {f"helper_sequence_{index:02d}" for index in range(1, 13)} | {
    f"helper_sequence_{index:02d}" for index in range(14, 21)
}

PROFILE_EXPECTATIONS = {
    "easy": {
        "service_aslr": False,
        "service_dep": False,
        "helper_aslr": False,
        "helper_dep": False,
        "required": {"helper_sequence_01", "helper_sequence_21", "helper_sequence_22"},
        "forbidden": ROP_SEQUENCES - {"helper_sequence_01"} | {"helper_sequence_13"},
        "markers": [b"request contained a leading NUL"],
        "absent_markers": [b"[seh]", b"ROP target marker", b"LEAK:"],
    },
    "seh": {
        "service_aslr": False,
        "service_dep": False,
        "helper_aslr": False,
        "helper_dep": False,
        "required": {"helper_sequence_13"},
        "forbidden": ROP_SEQUENCES | {"helper_sequence_21", "helper_sequence_22"},
        "markers": [b"[seh] handler reached"],
        "absent_markers": [b"ROP target marker", b"LEAK:"],
    },
    "dep": {
        "service_aslr": False,
        "service_dep": True,
        "helper_aslr": False,
        "helper_dep": True,
        "required": ROP_SEQUENCES | {"helper_memory_protect", "helper_writable_slot"},
        "forbidden": {"helper_sequence_13", "helper_sequence_21", "helper_sequence_22"},
        "markers": [b"ROP target marker reached"],
        "absent_markers": [b"[seh]", b"LEAK:"],
    },
    "aslr_dep": {
        "service_aslr": True,
        "service_dep": True,
        "helper_aslr": True,
        "helper_dep": True,
        "required": ROP_SEQUENCES | {"helper_memory_protect", "helper_writable_slot"},
        "forbidden": {"helper_sequence_13", "helper_sequence_21", "helper_sequence_22"},
        "markers": [b"ROP target marker reached", b"LEAK:"],
        "absent_markers": [b"[seh]"],
    },
}


def check(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def verify(profile: str, service_path: Path, helper_path: Path) -> list[str]:
    expected = PROFILE_EXPECTATIONS[profile]
    service = PEFile(service_path)
    helper = PEFile(helper_path)
    errors: list[str] = []

    check(service.machine == IMAGE_FILE_MACHINE_I386, "service is not x86", errors)
    check(helper.machine == IMAGE_FILE_MACHINE_I386, "helper is not x86", errors)
    check(service.dynamic_base() == expected["service_aslr"], "service ASLR flag mismatch", errors)
    check(service.nx_compatible() == expected["service_dep"], "service DEP flag mismatch", errors)
    check(helper.dynamic_base() == expected["helper_aslr"], "helper ASLR flag mismatch", errors)
    check(helper.nx_compatible() == expected["helper_dep"], "helper DEP flag mismatch", errors)

    if not expected["helper_aslr"]:
        check(helper.image_base == 0x62500000, "helper preferred base is not 0x62500000", errors)
        check(helper.relocations_stripped(), "fixed helper still contains relocations", errors)
    if profile == "seh":
        check(not helper.safe_seh_enabled(), "helper unexpectedly has a SafeSEH table", errors)
        for sequence in (bytes.fromhex("FF E4"), bytes.fromhex("FF D4"), bytes.fromhex("54 C3")):
            check(
                not helper.executable_contains(sequence),
                f"SEH helper contains unintended direct-stack sequence {sequence.hex(' ')}",
                errors,
            )

    exports = helper.exports()
    for name in expected["required"]:
        check(name in exports, f"helper is missing required export {name}", errors)
    for name in expected["forbidden"]:
        check(name not in exports, f"helper exposes out-of-profile primitive {name}", errors)

    for name in expected["required"] & SEQUENCES.keys():
        actual = helper.bytes_at_export(name, len(SEQUENCES[name]))
        check(actual == SEQUENCES[name], f"{name} bytes are {actual.hex(' ')}", errors)

    if profile in {"dep", "aslr_dep"}:
        check(b"VirtualProtect\0" in helper.data, "helper has no VirtualProtect import", errors)

    check(b"memcpy\0" in service.data, "service has no visible vulnerable-copy import", errors)
    for marker in expected["markers"]:
        check(marker in service.data, f"service is missing marker {marker!r}", errors)
    for marker in expected["absent_markers"]:
        check(marker not in service.data, f"service contains out-of-profile marker {marker!r}", errors)
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted(PROFILE_EXPECTATIONS), required=True)
    parser.add_argument("--service", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    return parser.parse_args()


def print_report(profile: str, service_path: Path, helper_path: Path) -> None:
    service = PEFile(service_path)
    helper = PEFile(helper_path)
    exports = helper.exports()
    print(
        f"[OK] service: ASLR={'on' if service.dynamic_base() else 'off'} "
        f"DEP={'on' if service.nx_compatible() else 'off'}"
    )
    print(
        f"[OK] helper: base=0x{helper.image_base:08X} "
        f"ASLR={'on' if helper.dynamic_base() else 'off'} "
        f"DEP={'on' if helper.nx_compatible() else 'off'} "
        f"SafeSEH={'on' if helper.safe_seh_enabled() else 'off'}"
    )
    required = PROFILE_EXPECTATIONS[profile]["required"]
    va_label = "preferred_VA" if helper.dynamic_base() else "VA"
    for name in sorted(required & SEQUENCES.keys()):
        rva = exports[name]
        sequence = SEQUENCES[name]
        print(
            f"[OK] {name}: RVA=0x{rva:08X} "
            f"{va_label}=0x{helper.image_base + rva:08X} bytes={sequence.hex(' ')}"
        )
    for name in ("helper_memory_protect", "helper_writable_slot"):
        if name in required:
            rva = exports[name]
            print(
                f"[OK] {name}: RVA=0x{rva:08X} "
                f"{va_label}=0x{helper.image_base + rva:08X}"
            )


def main() -> int:
    args = parse_args()
    try:
        errors = verify(args.profile, args.service, args.helper)
    except (OSError, VerificationError, struct.error, UnicodeError) as error:
        print(f"[FAIL] {error}")
        return 1
    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    print_report(args.profile, args.service, args.helper)
    print(f"[PASS] {args.profile}: mitigations, profile isolation, and primitives verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
