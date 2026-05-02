from __future__ import annotations


def format_c_array(data: bytes, var_name: str = "payload", line_width: int = 12) -> str:
    chunks = [data[index : index + line_width] for index in range(0, len(data), line_width)]
    lines = [", ".join(f"0x{byte:02x}" for byte in chunk) for chunk in chunks]
    body = ",\n    ".join(lines)
    return (
        f"unsigned char {var_name}[] = {{\n"
        f"    {body}\n"
        "};\n"
        f"unsigned int {var_name}_len = {len(data)};"
    )
