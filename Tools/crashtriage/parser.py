import re

from .models import ParsedCrash, RegisterValue

REGISTER_NAMES = {
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESI",
    "EDI",
    "EBP",
    "ESP",
    "EIP",
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RBP",
    "RSP",
    "RIP",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
}

REGISTER_RE = re.compile(
    r"\b(?P<reg>EIP|ESP|EBP|EAX|EBX|ECX|EDX|ESI|EDI|"
    r"RIP|RSP|RBP|RAX|RBX|RCX|RDX|RSI|RDI|R(?:1[0-5]|[89]))\b"
    r"\s*(?:=|:|\s)\s*(?P<value>0x[0-9a-fA-F]+|[0-9a-fA-F]{4,16})\b",
    re.IGNORECASE,
)

EXCEPTION_HEX_RE = re.compile(r"\b(c0000005)\b", re.IGNORECASE)
EXCEPTION_VALUE_RE = re.compile(
    r"\b(?:ExceptionAddress|Faulting(?:\s+address)?|Attempt(?:ed)?\s+to\s+(?:read|write))\b.*?"
    r"(0x[0-9a-fA-F]+|[0-9a-fA-F]{8,16})",
    re.IGNORECASE,
)

GENERIC_HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{8,16}\b")


def _normalize_hex(value: str) -> str:
    normalized = value.lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    if len(normalized) % 2 == 1:
        normalized = "0" + normalized
    return normalized


def parse_dump(text: str) -> ParsedCrash:
    registers: list[RegisterValue] = []
    exception = None
    exception_values: list[str] = []
    seen_registers: set[tuple[str, str]] = set()
    seen_exception_values: set[str] = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        exception_match = EXCEPTION_HEX_RE.search(line)
        if exception_match:
            exception = exception_match.group(1).lower()
        elif exception is None and "access violation" in line.lower():
            exception = "access violation"

        for match in REGISTER_RE.finditer(line):
            reg = match.group("reg").upper()
            if reg not in REGISTER_NAMES:
                continue
            value_hex = _normalize_hex(match.group("value"))
            key = (reg, value_hex)
            if key in seen_registers:
                continue
            seen_registers.add(key)
            registers.append(
                RegisterValue(
                    name=reg,
                    value_hex=value_hex,
                    width_bytes=len(value_hex) // 2,
                    source_line=line,
                )
            )

        for match in EXCEPTION_VALUE_RE.finditer(line):
            normalized = _normalize_hex(match.group(1))
            if normalized in seen_exception_values:
                continue
            seen_exception_values.add(normalized)
            exception_values.append(normalized)

    if not registers:
        # Useful fallback for lines that include only faulting values.
        for token in GENERIC_HEX_RE.findall(text):
            normalized = _normalize_hex(token)
            if normalized in seen_exception_values:
                continue
            seen_exception_values.add(normalized)
            exception_values.append(normalized)
            if len(exception_values) >= 3:
                break

    return ParsedCrash(
        registers=registers,
        exception=exception,
        exception_values=exception_values,
    )
