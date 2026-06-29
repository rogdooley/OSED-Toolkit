from pathlib import Path


def _quote(text: str) -> str:
    if " " in text:
        return f'\\"{text}\\"'
    return text


def render_capture_script(
    breakpoint_expr: str,
    dump_expr: str,
    dump_path: Path,
    dump_size: int = 0x10,
) -> str:

    dump = _quote(str(dump_path))

    return (
        "sxd ibp\n"
        "sxd ld\n"
        f"bp {breakpoint_expr} "
        f'".writemem {dump} ({dump_expr}) L0x{dump_size:x}; q"\n'
        "g\n"
    )
