from __future__ import annotations

from shellforge.analysis.pe_exports import (
    parse_portable_executable,
    parse_pe32_exports,
    resolve_export_by_hash,
    resolve_export_by_name,
)
from shellforge.hashes.ror13 import ROR13HashProvider
from tests.shellforge.pe_fixture import build_minimal_pe32_plus_with_export, build_minimal_pe32_with_export


def test_parse_pe32_exports_enumerates_named_exports() -> None:
    pe_bytes = build_minimal_pe32_with_export(export_name="DemoExport", export_rva=0x1122)
    exports = parse_pe32_exports(pe_bytes)
    assert len(exports) == 1
    assert exports[0].ordinal == 1
    assert exports[0].name == "DemoExport"
    assert exports[0].rva == 0x1122


def test_resolve_export_by_name() -> None:
    exports = parse_pe32_exports(build_minimal_pe32_with_export(export_name="SampleName"))
    resolved = resolve_export_by_name(exports, "samplename")
    assert resolved is not None
    assert resolved.name == "SampleName"


def test_resolve_export_by_hash() -> None:
    provider = ROR13HashProvider()
    exports = parse_pe32_exports(build_minimal_pe32_with_export(export_name="HashTarget"))
    target_hash = provider.compute("HashTarget")
    resolved = resolve_export_by_hash(exports, target_hash, provider)
    assert resolved is not None
    assert resolved.name == "HashTarget"


def test_parse_portable_executable_supports_pe32_plus() -> None:
    parsed = parse_portable_executable(build_minimal_pe32_plus_with_export(export_name="Export64", export_rva=0x2200))
    assert parsed.format == "PE32+"
    assert parsed.machine == 0x8664
    assert parsed.machine_name == "AMD64"
    assert parsed.image_base == 0x140000000
    assert parsed.entrypoint_rva == 0x1000
    assert len(parsed.sections) == 1
    assert parsed.exports[0].name == "Export64"
    assert parsed.exports[0].rva == 0x2200
