from __future__ import annotations


def format_python_bytes(data: bytes, line_width: int = 16) -> str:
    chunks = [data[index : index + line_width] for index in range(0, len(data), line_width)]
    lines = [f'    b"{"".join(f"\\x{byte:02x}" for byte in chunk)}"' for chunk in chunks] or ['    b""']
    return "payload = (\n" + "\n".join(lines) + "\n)"
