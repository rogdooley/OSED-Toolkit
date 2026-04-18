from pathlib import Path

from . import build_egg, build_stage2, choose_hunter, debug_hunter_info, exam_workflow_note


def to_hex(buf: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in buf)


def to_python_bytes_literal(buf: bytes, var_name: str) -> str:
    return f'{var_name} = b"{to_hex(buf)}"'


def to_c_array(buf: bytes, var_name: str) -> str:
    body = ",".join(f"0x{b:02x}" for b in buf)
    return f"unsigned char {var_name}[] = {{{body}}};"


def to_csharp_array(buf: bytes, var_name: str) -> str:
    body = ", ".join(f"0x{b:02x}" for b in buf)
    return f"byte[] {var_name} = new byte[] {{ {body} }};"


def to_powershell_byte_array(buf: bytes, var_name: str) -> str:
    body = ",".join(f"0x{b:02x}" for b in buf)
    return f"[Byte[]]${var_name} = {body}"


def main() -> None:
    tag = b"W00T"
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
    egg = build_egg(tag)
    stage2 = build_stage2(tag, payload)

    debug_hunter_info(selected.name, hunter)
    print(f"[+] Egg marker: {egg!r}")
    print(f"[+] Egg marker (escaped): {to_hex(egg)}")

    print("\nPython-ready:")
    print(to_python_bytes_literal(hunter, "hunter"))
    print(to_python_bytes_literal(egg, "egg"))
    print(to_python_bytes_literal(stage2, "stage2"))

    print("\nOther formats:")
    print(to_c_array(hunter, "hunter"))
    print(to_csharp_array(hunter, "hunter"))
    print(to_powershell_byte_array(hunter, "hunter"))

    print("\nStage2 preview:")
    print(f'b"{to_hex(stage2[:64])}..."')

    Path("hunter.bin").write_bytes(hunter)
    Path("stage2.bin").write_bytes(stage2)

    print("\n[+] Files written: hunter.bin, stage2.bin")
    print("\n" + exam_workflow_note())


if __name__ == "__main__":
    main()
