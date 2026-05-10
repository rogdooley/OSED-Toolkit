from enum import StrEnum


class CommandId(StrEnum):
    CLI_PARSE = "cli.parse"
    BUILD_DEMO = "build.demo"
    BUILD_CALC = "build.calc"
    HASH_COMPUTE = "hash.compute"
    HASH_RESOLVE = "hash.resolve"
    CHECK_BADCHARS = "check.badchars"
    ENCODE_XOR = "encode.xor"
    ENCODE_DECODE = "encode.decode"
    PE_LIST = "pe.list"
    PE_RESOLVE_NAME = "pe.resolve_name"
    PE_RESOLVE_HASH = "pe.resolve_hash"
    PE_IMPORTS = "pe.imports"
    PE_RVA_TO_FILE = "pe.rva_to_file"
    PE_FILE_TO_RVA = "pe.file_to_rva"
    PE_RVA_TO_VA = "pe.rva_to_va"
    PE_VA_TO_RVA = "pe.va_to_rva"
    DISASM_ANALYZE = "disasm.analyze"
    ANALYZE_STATIC = "analyze.static"
