from __future__ import annotations


def ror(value: int, count: int, bits: int = 32) -> int:
    """
    Rotate right.
    """
    h = (value >> count % bits | value << (32 - count)) & 0xFFFFFFFF
    return h


def compute_hash(name: str) -> int:
    """
    OSED-style ROR13 hash.

    Equivalent assembly:

        xor eax, eax
        cdq

    loop:
        lodsb
        test al, al
        jz done

        ror edx, 13
        add edx, eax
    """
    hash = 0
    for char in name:
        hash = ror(hash, 13)
        hash += ord(char)

    return hash


def main() -> None:
    apis: list[str] = [
        "WinExec",
        "ExitProcess",
        "LoadLibraryA",
        "GetProcAddress",
        "WSAStartup",
        "WSASocketA",
        "connect",
        "CreateProcessA",
    ]

    for api in apis:
        api_hash: int = compute_hash(api)
        print(f"{api:<20} 0x{api_hash:08x}")


if __name__ == "__main__":
    main()
