from __future__ import annotations

import struct


def _build_minimal_pe_with_export(
    *,
    optional_magic: int,
    machine: int,
    optional_header_size: int,
    export_name: str,
    export_rva: int,
) -> bytes:
    image = bytearray(0x400)

    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)

    pe_offset = 0x80
    image[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    coff_offset = pe_offset + 4
    struct.pack_into(
        "<HHIIIHH",
        image,
        coff_offset,
        machine,
        1,  # NumberOfSections
        0,
        0,
        0,
        optional_header_size,
        0x210E,
    )

    optional_offset = coff_offset + 20
    struct.pack_into("<H", image, optional_offset, optional_magic)
    struct.pack_into("<I", image, optional_offset + 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", image, optional_offset + 20, 0x1000)  # BaseOfCode

    if optional_magic == 0x10B:
        struct.pack_into("<I", image, optional_offset + 24, 0x1000)  # BaseOfData
        struct.pack_into("<I", image, optional_offset + 28, 0x400000)  # ImageBase
        number_of_rva_offset = 92
        data_directory_offset = 96
    elif optional_magic == 0x20B:
        struct.pack_into("<Q", image, optional_offset + 24, 0x140000000)  # ImageBase
        number_of_rva_offset = 108
        data_directory_offset = 112
    else:
        raise ValueError("unsupported fixture optional header type")

    struct.pack_into("<I", image, optional_offset + 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", image, optional_offset + 36, 0x200)  # FileAlignment
    struct.pack_into("<I", image, optional_offset + 56, 0x2000)  # SizeOfImage
    struct.pack_into("<I", image, optional_offset + 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<H", image, optional_offset + 68, 3)  # Subsystem (CUI)
    struct.pack_into("<I", image, optional_offset + number_of_rva_offset, 16)  # NumberOfRvaAndSizes

    export_dir_rva = 0x1000
    export_dir_size = 0x100
    struct.pack_into("<II", image, optional_offset + data_directory_offset, export_dir_rva, export_dir_size)

    section_offset = optional_offset + optional_header_size
    image[section_offset : section_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", image, section_offset + 8, 0x1000)  # VirtualSize
    struct.pack_into("<I", image, section_offset + 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", image, section_offset + 16, 0x200)  # SizeOfRawData
    struct.pack_into("<I", image, section_offset + 20, 0x200)  # PointerToRawData
    struct.pack_into("<I", image, section_offset + 36, 0x60000020)

    def rva_to_offset(rva: int) -> int:
        return 0x200 + (rva - 0x1000)

    export_offset = rva_to_offset(export_dir_rva)
    dll_name_rva = 0x1040
    functions_rva = 0x1050
    names_rva = 0x1060
    ordinals_rva = 0x1068
    symbol_name_rva = 0x1070

    struct.pack_into(
        "<IIHHIIIIIII",
        image,
        export_offset,
        0,
        0,
        0,
        0,
        dll_name_rva,
        1,
        1,
        1,
        functions_rva,
        names_rva,
        ordinals_rva,
    )

    image[rva_to_offset(dll_name_rva) : rva_to_offset(dll_name_rva) + 12] = b"fixture.dll\x00"
    struct.pack_into("<I", image, rva_to_offset(functions_rva), export_rva)
    struct.pack_into("<I", image, rva_to_offset(names_rva), symbol_name_rva)
    struct.pack_into("<H", image, rva_to_offset(ordinals_rva), 0)
    image[rva_to_offset(symbol_name_rva) : rva_to_offset(symbol_name_rva) + len(export_name) + 1] = (
        export_name.encode("ascii") + b"\x00"
    )
    return bytes(image)


def build_minimal_pe32_with_export(*, export_name: str = "DemoExport", export_rva: int = 0x1100) -> bytes:
    return _build_minimal_pe_with_export(
        optional_magic=0x10B,
        machine=0x014C,
        optional_header_size=0xE0,
        export_name=export_name,
        export_rva=export_rva,
    )


def build_minimal_pe32_plus_with_export(*, export_name: str = "DemoExport64", export_rva: int = 0x1100) -> bytes:
    return _build_minimal_pe_with_export(
        optional_magic=0x20B,
        machine=0x8664,
        optional_header_size=0xF0,
        export_name=export_name,
        export_rva=export_rva,
    )
