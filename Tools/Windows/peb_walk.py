import ctypes
from typing import Generator, Iterable


def read_u32(addr: int) -> int:
    return ctypes.c_uint32.from_address(addr).value


## https://www.bordergate.co.uk/function-name-hashing/
def ror(value: int, bits: int) -> int:
    return (value >> bits | value << (32 - bits)) & 0xFFFFFFFF


def iter_utf16le_null(name: str, uppercase: bool = True) -> Generator[int, None, None]:
    if uppercase:
        name = name.upper()
    for char in name:
        yield ord(char) & 0xFF
        yield 0

    yield 0
    yield 0


def iter_ascii_null(name: str) -> Generator[int, None, None]:
    for char in name:
        yield ord(char)

    yield 0


def hash_bytes(stream: Iterable[int], bits: int = 13) -> int:
    hash = 0
    for byte in stream:
        hash = ror(hash, bits)
        hash += byte
        hash &= 0xFFFFFFFF

    return hash


def hash_api(module: str, function: str, bits: int = 13) -> int:
    module_hash = hash_bytes(iter_utf16le_null(module))
    function_hash = hash_bytes(iter_ascii_null(function))
    return (module_hash + function_hash) & 0xFFFFFFFF


def main():

    ntdll = ctypes.WinDLL("ntdll")
    teb_addr = ctypes.cast(ntdll.NtCurrentTeb(), ctypes.c_void_p).value
    peb_addr = read_u32(teb_addr + 0x30)
    ldr_addr = read_u32(peb_addr + 0x0C)
    head = ldr_addr + 0x1C
    node = read_u32(head)

    print(f"TEB Adrress: 0x{teb_addr:08x}")
    print(f"PEB Address: 0x{peb_addr:08x}")
    print(
        f"LDR Address: 0x{ldr_addr:08x}"
    )  # head == &PEB_LDR_DATA.InInitializationOrderModuleList

    idx = 0

    while node != head:
        entry = node - 0x10
        dll_base = read_u32(entry + 0x18)
        # name_len = read_u32(entry + 0x2C) & 0xFFFF
        name_len = ctypes.c_ushort.from_address(entry + 0x2C).value
        name_ptr = read_u32(entry + 0x30)
        name = ctypes.wstring_at(
            name_ptr, name_len // 2
        )  # unicode string is length in bytes and not characters (2 bytes/char)

        api_hash = hash_api(name, "WinExec")

        print(f"[{idx}] {name:<30} base=0x{dll_base:08x} api_hash=0x{api_hash:08x}")
        if name.lower() == "kernel32.dll":
            print(f"[+] Found kernel32.dll at 0x{dll_base:08x}")
            print(f"[+] KERNEL32.DLL!WinExec hash: 0x{hash_api(name, 'WinExec'):08x}")
            break

        idx += 1

        node = read_u32(node)


if __name__ == "__main__":
    main()
