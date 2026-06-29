from pathlib import Path

from backend.wds import render_capture_wds

print(
    render_capture_wds(
        breakpoint_expr="vulnapp2+0x1000",
        dump_expr="poi(@esp+8)",
        dump_path=Path(r"C:\dbg\dump.bin"),
    )
)
w
