import ast
import re


class ParseError(ValueError):
    pass


_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")
_C_ARRAY_RE = re.compile(r"0x[0-9a-fA-F]{1,2}")
_ESCAPED_HEX_RE = re.compile(r"\\x[0-9a-fA-F]{2}")


def _strip_hex_noise(s: str) -> str:
    # Remove common separators users paste: spaces, commas, newlines.
    return s.replace(",", "").replace(" ", "").replace("\n", "").replace("\t", "")


def parse_hex(s: str) -> bytes:
    """
    Parse a raw hex string like:
      - deadbeef
      - 0xdeadbeef
      - de ad be ef
      - de,ad,be,ef
    """
    if not isinstance(s, str) or not s.strip():
        raise ParseError("empty hex input")

    raw = _strip_hex_noise(s.strip())
    if raw.startswith("0x") or raw.startswith("0X"):
        raw = raw[2:]

    if not raw:
        raise ParseError("empty hex input after stripping separators")

    if len(raw) % 2 != 0:
        raise ParseError("hex string must have an even number of nybbles")

    if not _HEX_RE.match(raw):
        raise ParseError("invalid characters in hex string")

    try:
        return bytes.fromhex(raw)
    except ValueError as exc:
        raise ParseError(str(exc)) from exc


def parse_escaped_hex(s: str) -> bytes:
    """
    Parse an escaped hex string like:
      - \\x90\\x90\\xcc
      - "\\x90\\x90\\xcc"
    """
    if not isinstance(s, str) or not s.strip():
        raise ParseError("empty escaped-hex input")

    text = s.strip().strip('"').strip("'")
    matches = _ESCAPED_HEX_RE.findall(text)
    if not matches:
        raise ParseError("no \\\\xNN bytes found")
    return bytes(int(m[2:], 16) for m in matches)


def parse_c_array(s: str) -> bytes:
    """
    Parse a C-style byte array initializer snippet like:
      unsigned char sc[] = { 0x90, 0x90, 0xcc };
      {0x90,0x90,0xcc}
    """
    if not isinstance(s, str) or not s.strip():
        raise ParseError("empty C-array input")

    matches = _C_ARRAY_RE.findall(s)
    if not matches:
        raise ParseError("no 0xNN tokens found in C-array input")

    out = bytearray()
    for token in matches:
        out.append(int(token, 16))
    return bytes(out)


def parse_py_bytes_literal(s: str) -> bytes:
    """
    Parse a Python bytes literal like:
      b\"\\x90\\x90\\xcc\"
    Uses ast.literal_eval to avoid executing code.
    """
    if not isinstance(s, str) or not s.strip():
        raise ParseError("empty python-bytes input")

    text = s.strip()
    try:
        value = ast.literal_eval(text)
    except Exception as exc:
        raise ParseError(f"invalid python literal: {exc}") from exc

    if not isinstance(value, (bytes, bytearray)):
        raise ParseError("python literal did not evaluate to bytes/bytearray")
    return bytes(value)
