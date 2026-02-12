from __future__ import annotations


def _chunk(data: bytes, n: int) -> list[bytes]:
    return [data[i : i + n] for i in range(0, len(data), n)]


def format_bytes(
    data: bytes,
    *,
    fmt: str,
    width: int = 16,
    var_name: str = "sc",
) -> str:
    """
    Format bytes for copy/paste into exploit skeletons.

    fmt:
      - "hex": deadbeef
      - "escaped": \\xde\\xad\\xbe\\xef
      - "py": sc = b"\\xde\\xad..."
      - "c": unsigned char sc[] = { 0xde, 0xad, ... };
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    data = bytes(data)

    if width <= 0:
        raise ValueError("width must be positive")

    fmt = fmt.lower()
    if fmt == "hex":
        return data.hex()

    if fmt == "escaped":
        return "".join(f"\\x{b:02x}" for b in data)

    if fmt == "py":
        # Keep it readable: wrap at width bytes per line.
        lines = []
        for part in _chunk(data, width):
            lines.append('"' + "".join(f"\\x{b:02x}" for b in part) + '"')
        if not lines:
            return f"{var_name} = b''"
        joined = " \\\n    ".join(lines)
        return f"{var_name} = b{joined}"

    if fmt == "c":
        parts = [f"0x{b:02x}" for b in data]
        if not parts:
            return f"unsigned char {var_name}[] = {{}};"
        lines = []
        for chunk in _chunk(bytes(range(len(parts))), width):
            # chunk is indices; keep stable.
            idxs = list(chunk)
            line = ", ".join(parts[i] for i in idxs)
            lines.append("  " + line)
        body = ",\n".join(lines)
        return f"unsigned char {var_name}[] = {{\n{body}\n}};"

    raise ValueError(f"unknown fmt: {fmt}")
