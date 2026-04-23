from .analyze import ShellcodeReport, analyze_shellcode, find_badchars
from .shellcode_encoder import (
    ShellcodeEncodingError,
    XorEncodingMetadata,
    XorEncodingResult,
    contains_badchars,
    encode_xor,
    encode_xor_with_metadata,
)
from .formatting import format_bytes
from .parsing import (
    ParseError,
    parse_c_array,
    parse_escaped_hex,
    parse_hex,
    parse_py_bytes_literal,
)

__all__ = [
    "ShellcodeReport",
    "ParseError",
    "analyze_shellcode",
    "ShellcodeEncodingError",
    "XorEncodingMetadata",
    "XorEncodingResult",
    "contains_badchars",
    "encode_xor",
    "encode_xor_with_metadata",
    "find_badchars",
    "format_bytes",
    "parse_c_array",
    "parse_escaped_hex",
    "parse_hex",
    "parse_py_bytes_literal",
]
