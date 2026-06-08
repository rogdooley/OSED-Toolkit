import argparse
import struct


def ip_to_bytes(ip: str) -> bytes:
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"Invalid IP: {ip}")
    return bytes(int(p) for p in parts)


def has_null(value: int, width: int = 4) -> bool:
    return any(((value >> (i * 8)) & 0xFF) == 0 for i in range(width))


def find_addend(
    packed: int, width: int = 4, base_addend: int | None = None
) -> tuple[int, int]:
    """
    Find smallest addend such that (packed + addend) is null-free.
    addend itself is also checked for null bytes.
    width: byte width of the value (4 for IP/port, 8 for 64-bit pointers)
    """
    mask = (1 << (width * 8)) - 1
    unit = sum(1 << (i * 8) for i in range(width))  # 0x01010101 or 0x0101010101010101
    candidate = base_addend if base_addend is not None else unit

    for _ in range(unit * 10):
        obfuscated = (packed + candidate) & mask
        if not has_null(obfuscated, width) and not has_null(candidate, width):
            return obfuscated, candidate
        candidate = (candidate + unit) & mask

    raise ValueError("Could not find a null-free addend")


def format_hex(value: int, width: int = 4) -> str:
    return f"0x{value:0{width * 2}x}"


def analyze(ip: str, base_addend: int | None = None) -> None:
    raw = ip_to_bytes(ip)
    ip_le = struct.unpack("<I", raw)[0]

    print(f"\n[*] IP: {ip}")
    print(f"    Raw (BE):     {' '.join(f'{b:02x}' for b in raw)}")
    print(f"    Packed (LE):  {format_hex(ip_le)}")
    print(f"    Has nulls:    {has_null(ip_le)}")

    if not has_null(ip_le):
        print("\n[+] No null bytes — use directly:")
        print(f"    value:        {format_hex(ip_le)}")
        return

    obfuscated, addend = find_addend(ip_le, width=4, base_addend=base_addend)

    print("\n[+] Null bytes present — addend obfuscation:")
    print(f"    addend:       {format_hex(addend)}")
    print(f"    obfuscated:   {format_hex(obfuscated)}")
    print(
        f"    verify:       {format_hex((obfuscated - addend) & 0xFFFFFFFF)}  (should match packed LE)"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IP → shellcode hex with null-byte avoidance"
    )
    parser.add_argument("ip", help="IPv4 address (e.g. 192.168.1.236)")
    parser.add_argument(
        "--addend",
        type=lambda x: int(x, 16),
        default=None,
        help="Base addend in hex (default: 0x01010101)",
    )
    args = parser.parse_args()
    analyze(args.ip, args.addend)


if __name__ == "__main__":
    main()
