from __future__ import annotations

from dataclasses import dataclass
import pathlib
import struct

from shellforge.contracts.errors import ErrorCode, ShellforgeError
from shellforge.interfaces import HashProvider

PE_MACHINE_NAMES: dict[int, str] = {
    0x014C: "I386",
    0x8664: "AMD64",
}


@dataclass(frozen=True, slots=True)
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    pointer_to_raw_data: int
    size_of_raw_data: int


@dataclass(frozen=True, slots=True)
class PEExport:
    ordinal: int
    name: str
    rva: int


@dataclass(frozen=True, slots=True)
class PortableExecutable:
    machine: int
    machine_name: str
    format: str
    image_base: int
    entrypoint_rva: int
    sections: list[PESection]
    exports: list[PEExport]


def _read_struct(data: bytes, offset: int, fmt: str) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ShellforgeError(
            ErrorCode.PARSE_ERROR,
            "invalid PE structure offset",
            details={"offset": offset, "size": size},
        )
    return struct.unpack_from(fmt, data, offset)


def _read_c_string(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        raise ShellforgeError(ErrorCode.PARSE_ERROR, "invalid string offset", details={"offset": offset})
    end = data.find(b"\x00", offset)
    if end == -1:
        raise ShellforgeError(ErrorCode.PARSE_ERROR, "unterminated string in PE", details={"offset": offset})
    return data[offset:end].decode("ascii", errors="strict")


def _rva_to_offset(rva: int, sections: list[PESection]) -> int:
    for section in sections:
        start = section.virtual_address
        end = start + max(section.virtual_size, section.size_of_raw_data)
        if start <= rva < end:
            return section.pointer_to_raw_data + (rva - start)
    raise ShellforgeError(
        ErrorCode.INVALID_RVA,
        f"RVA 0x{rva:08x} is outside mapped sections",
        details={"rva": f"0x{rva:08x}"},
    )


def _parse_sections(data: bytes, section_offset: int, count: int) -> list[PESection]:
    sections: list[PESection] = []
    for index in range(count):
        entry_offset = section_offset + (index * 40)
        name_raw = _read_struct(data, entry_offset, "<8s")[0]
        virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data = _read_struct(
            data, entry_offset + 8, "<IIII"
        )
        name = name_raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        sections.append(
            PESection(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                pointer_to_raw_data=pointer_to_raw_data,
                size_of_raw_data=size_of_raw_data,
            )
        )
    return sections


def _parse_exports(data: bytes, sections: list[PESection], export_rva: int, export_size: int) -> list[PEExport]:
    if export_rva == 0 or export_size == 0:
        return []

    export_offset = _rva_to_offset(export_rva, sections)
    (
        _characteristics,
        _timestamp,
        _major,
        _minor,
        _name_rva,
        base_ordinal,
        number_of_functions,
        number_of_names,
        address_of_functions_rva,
        address_of_names_rva,
        address_of_ordinals_rva,
    ) = _read_struct(data, export_offset, "<IIHHIIIIIII")

    if number_of_functions == 0 or number_of_names == 0:
        return []

    functions_offset = _rva_to_offset(address_of_functions_rva, sections)
    names_offset = _rva_to_offset(address_of_names_rva, sections)
    ordinals_offset = _rva_to_offset(address_of_ordinals_rva, sections)

    exports: list[PEExport] = []
    for index in range(number_of_names):
        name_rva = _read_struct(data, names_offset + (index * 4), "<I")[0]
        name_offset = _rva_to_offset(name_rva, sections)
        name = _read_c_string(data, name_offset)
        ordinal_index = _read_struct(data, ordinals_offset + (index * 2), "<H")[0]
        if ordinal_index >= number_of_functions:
            raise ShellforgeError(
                ErrorCode.PARSE_ERROR,
                "invalid ordinal index in export table",
                details={"ordinal_index": ordinal_index, "number_of_functions": number_of_functions},
            )
        function_rva = _read_struct(data, functions_offset + (ordinal_index * 4), "<I")[0]
        exports.append(PEExport(ordinal=base_ordinal + ordinal_index, name=name, rva=function_rva))
    return sorted(exports, key=lambda item: item.ordinal)


def parse_portable_executable(data: bytes) -> PortableExecutable:
    e_magic = _read_struct(data, 0x00, "<H")[0]
    if e_magic != 0x5A4D:
        raise ShellforgeError(
            ErrorCode.INVALID_PE_SIGNATURE,
            "Missing MZ header",
            details={"offset": 0},
        )

    pe_offset = _read_struct(data, 0x3C, "<I")[0]
    signature = _read_struct(data, pe_offset, "<I")[0]
    if signature != 0x00004550:
        raise ShellforgeError(
            ErrorCode.INVALID_NT_SIGNATURE,
            "Missing PE signature",
            details={"offset": pe_offset},
        )

    machine = _read_struct(data, pe_offset + 4, "<H")[0]
    machine_name = PE_MACHINE_NAMES.get(machine, "UNKNOWN")
    number_of_sections = _read_struct(data, pe_offset + 6, "<H")[0]
    optional_header_size = _read_struct(data, pe_offset + 20, "<H")[0]
    optional_offset = pe_offset + 24
    optional_magic = _read_struct(data, optional_offset, "<H")[0]

    if optional_magic == 0x10B:
        if optional_header_size < 0x60:
            raise ShellforgeError(
                ErrorCode.INVALID_OPTIONAL_HEADER,
                "PE32 optional header is too small",
                details={"size": optional_header_size},
            )
        pe_format = "PE32"
        entrypoint_rva = _read_struct(data, optional_offset + 16, "<I")[0]
        image_base = _read_struct(data, optional_offset + 28, "<I")[0]
        number_of_rva_and_sizes = _read_struct(data, optional_offset + 92, "<I")[0]
        data_directory_offset = optional_offset + 96
    elif optional_magic == 0x20B:
        if optional_header_size < 0x70:
            raise ShellforgeError(
                ErrorCode.INVALID_OPTIONAL_HEADER,
                "PE32+ optional header is too small",
                details={"size": optional_header_size},
            )
        pe_format = "PE32+"
        entrypoint_rva = _read_struct(data, optional_offset + 16, "<I")[0]
        image_base = _read_struct(data, optional_offset + 24, "<Q")[0]
        number_of_rva_and_sizes = _read_struct(data, optional_offset + 108, "<I")[0]
        data_directory_offset = optional_offset + 112
    else:
        raise ShellforgeError(
            ErrorCode.UNSUPPORTED_PE_FORMAT,
            "unsupported PE optional header magic",
            details={"optional_magic": f"0x{optional_magic:04x}"},
        )

    if number_of_rva_and_sizes < 1:
        export_rva = 0
        export_size = 0
    else:
        export_rva, export_size = _read_struct(data, data_directory_offset, "<II")

    section_offset = optional_offset + optional_header_size
    sections = _parse_sections(data, section_offset, number_of_sections)
    exports = _parse_exports(data, sections, export_rva, export_size)

    return PortableExecutable(
        machine=machine,
        machine_name=machine_name,
        format=pe_format,
        image_base=image_base,
        entrypoint_rva=entrypoint_rva,
        sections=sections,
        exports=exports,
    )


def parse_portable_executable_from_path(path: str) -> PortableExecutable:
    return parse_portable_executable(pathlib.Path(path).read_bytes())


def parse_pe32_exports(data: bytes) -> list[PEExport]:
    parsed = parse_portable_executable(data)
    if parsed.format != "PE32":
        raise ShellforgeError(
            ErrorCode.UNSUPPORTED_PE_FORMAT,
            "only PE32 is supported by parse_pe32_exports",
            details={"format": parsed.format},
        )
    return parsed.exports


def parse_pe32_exports_from_path(path: str) -> list[PEExport]:
    return parse_pe32_exports(pathlib.Path(path).read_bytes())


def resolve_export_by_name(exports: list[PEExport], name: str) -> PEExport | None:
    lookup = name.lower()
    for item in exports:
        if item.name.lower() == lookup:
            return item
    return None


def resolve_export_by_hash(exports: list[PEExport], hash_value: int, provider: HashProvider) -> PEExport | None:
    for item in exports:
        if provider.compute(item.name) == hash_value:
            return item
    return None
