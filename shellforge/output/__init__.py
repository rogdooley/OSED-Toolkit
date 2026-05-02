from shellforge.output.c_array import format_c_array
from shellforge.output.hex_dump import format_hex_dump
from shellforge.output.python_bytes import format_python_bytes
from shellforge.output.raw import format_raw

FORMATTERS = {
    "raw": format_raw,
    "python": format_python_bytes,
    "c": format_c_array,
    "hex": format_hex_dump,
}

__all__ = ["FORMATTERS", "format_raw", "format_python_bytes", "format_c_array", "format_hex_dump"]
