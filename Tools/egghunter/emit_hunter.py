from pathlib import Path

from . import build_stage2, choose_hunter, debug_hunter_info, exam_workflow_note


def to_hex(buf: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in buf)


def main() -> None:
    tag = b"w00t"
    badchars = b"\x00\x0a\x0d"
    target = "win10_x86"
    payload = b"\x90" * 100

    selected = choose_hunter(
        tag=tag,
        excluded=badchars,
        target=target,
        prefer_seh=False,
        debug=True,
    )

    hunter = selected.shellcode
    stage2 = build_stage2(tag, payload)

    debug_hunter_info(selected.name, hunter)

    print("\nHunter:")
    print(f'b"{to_hex(hunter)}"')

    print("\nStage2 preview:")
    print(f'b"{to_hex(stage2[:64])}..."')

    Path("hunter.bin").write_bytes(hunter)
    Path("stage2.bin").write_bytes(stage2)

    print("\n[+] Files written: hunter.bin, stage2.bin")
    print("\n" + exam_workflow_note())


if __name__ == "__main__":
    main()
