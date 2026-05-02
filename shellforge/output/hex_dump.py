from __future__ import annotations


def format_hex_dump(data: bytes, line_width: int = 16) -> str:
    rows: list[str] = []
    for offset in range(0, len(data), line_width):
        chunk = data[offset : offset + line_width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        rows.append(f"{offset:08x}  {hex_part:<{line_width * 3 - 1}}  |{ascii_part}|")
    return "\n".join(rows)
