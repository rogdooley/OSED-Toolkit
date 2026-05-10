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
class PEImport:
    dll: str
    name: str | None
    ordinal: int | None
    hint: int | None
    thunk_rva: int
    iat_rva: int


@dataclass(frozen=True, slots=True)
class PortableExecutable:
    machine: int
    machine_name: str
    format: str
    image_base: int
    entrypoint_rva: int
    sections: list[PESection]
    exports: list[PEExport]
    imports: list[PEImport]


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


def find_section_for_rva(rva: int, sections: list[PESection]) -> PESection | None:
    for section in sections:
        start = section.virtual_address
        end = start + max(section.virtual_size, section.size_of_raw_data)
        if start <= rva < end:
            return section
    return None


def rva_to_file_offset(rva: int, sections: list[PESection]) -> tuple[int, PESection | None]:
    section = find_section_for_rva(rva, sections)
    if section is None:
        raise ShellforgeError(
            ErrorCode.INVALID_RVA,
            f"RVA 0x{rva:08x} is outside mapped sections",
            details={"rva": f"0x{rva:08x}"},
        )
    return section.pointer_to_raw_data + (rva - section.virtual_address), section


def file_offset_to_rva(offset: int, sections: list[PESection]) -> tuple[int, PESection | None]:
    for section in sections:
        start = section.pointer_to_raw_data
        end = start + section.size_of_raw_data
        if start <= offset < end:
            return section.virtual_address + (offset - start), section
    raise ShellforgeError(
        ErrorCode.INVALID_RVA,
        f"File offset 0x{offset:08x} is outside mapped sections",
        details={"offset": f"0x{offset:08x}"},
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


def _parse_imports(data: bytes, sections: list[PESection], import_rva: int, import_size: int, pointer_size: int) -> list[PEImport]:
    if import_rva == 0 or import_size == 0:
        return []

    descriptor_offset = _rva_to_offset(import_rva, sections)
    imports: list[PEImport] = []

    for _index in range(4096):
        (
            original_first_thunk,
            _time_date_stamp,
            _forwarder_chain,
            name_rva,
            first_thunk,
        ) = _read_struct(data, descriptor_offset, "<IIIII")

        if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break

        dll_name = _read_c_string(data, _rva_to_offset(name_rva, sections))
        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = _rva_to_offset(thunk_rva, sections)
        iat_offset = _rva_to_offset(first_thunk, sections)

        for thunk_index in range(16384):
            if pointer_size == 8:
                thunk_value = _read_struct(data, thunk_offset + (thunk_index * 8), "<Q")[0]
                iat_value = _read_struct(data, iat_offset + (thunk_index * 8), "<Q")[0]
                ordinal_flag = 0x8000000000000000
            else:
                thunk_value = _read_struct(data, thunk_offset + (thunk_index * 4), "<I")[0]
                iat_value = _read_struct(data, iat_offset + (thunk_index * 4), "<I")[0]
                ordinal_flag = 0x80000000

            if thunk_value == 0 and iat_value == 0:
                break

            if (thunk_value & ordinal_flag) != 0:
                imports.append(
                    PEImport(
                        dll=dll_name,
                        name=None,
                        ordinal=thunk_value & 0xFFFF,
                        hint=None,
                        thunk_rva=thunk_rva + (thunk_index * pointer_size),
                        iat_rva=first_thunk + (thunk_index * pointer_size),
                    )
                )
                continue

            import_by_name_rva = int(thunk_value)
            import_by_name_offset = _rva_to_offset(import_by_name_rva, sections)
            hint = _read_struct(data, import_by_name_offset, "<H")[0]
            name = _read_c_string(data, import_by_name_offset + 2)
            imports.append(
                PEImport(
                    dll=dll_name,
                    name=name,
                    ordinal=None,
                    hint=hint,
                    thunk_rva=thunk_rva + (thunk_index * pointer_size),
                    iat_rva=first_thunk + (thunk_index * pointer_size),
                )
            )

        descriptor_offset += 20

    return imports


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
        pointer_size = 4
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
        pointer_size = 8
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
    if number_of_rva_and_sizes < 2:
        import_rva = 0
        import_size = 0
    else:
        import_rva, import_size = _read_struct(data, data_directory_offset + 8, "<II")

    section_offset = optional_offset + optional_header_size
    sections = _parse_sections(data, section_offset, number_of_sections)
    exports = _parse_exports(data, sections, export_rva, export_size)
    imports = _parse_imports(data, sections, import_rva, import_size, pointer_size)

    return PortableExecutable(
        machine=machine,
        machine_name=machine_name,
        format=pe_format,
        image_base=image_base,
        entrypoint_rva=entrypoint_rva,
        sections=sections,
        exports=exports,
        imports=imports,
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
