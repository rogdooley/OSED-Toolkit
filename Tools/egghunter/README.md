IMPORTANT:
Do not blindly trust generated opcodes.

Short jumps, relative calls, and offset-dependent instructions
may be incorrectly encoded by assemblers such as Keystone.

Always verify:
    - disassembly in WinDbg
    - control flow (especially jumps)
    - absence of badchars

Recommended validation:
    u <hunter_address>
    t / p stepping through execution

Usage as module:

```python
from Tools.egghunter import build, choose_hunter, build_stage2

hunter = build("x86_ntaccess", tag=b"w00t", syscall_id=0x1C6).shellcode
selected = choose_hunter(tag=b"w00t", excluded=b"\x00\x0a\x0d")
stage2 = build_stage2(b"w00t", b"\x90" * 100)
```

Canonical implementation lives in:
- `core.py`
- `__init__.py`

Optional example runner:
- `emit_hunter.py`

Unified Builder (new)

```python
from Tools.egghunter import EgghunterBuilder, EgghunterConfig

builder = EgghunterBuilder(
    EgghunterConfig(
        tag=b"LOKI",
        badchars=b"\x00\x0a\x0d",
        debug=True,
        output_asm=True,
        target="win10_x86",
    )
)

hunter = builder.build(strategy="seh_win10")
# or: strategy="syscall" / "seh_classic" / "auto"
```

Notes:
- `build(...)` always returns raw `bytes`.
- Tag must be exactly 4 bytes, and egg marker is internally `tag * 2`.
- Syscall strategy uses strict priority:
  1. `syscall_id_override`
  2. `resolve_syscall(target, ...)`
  3. fail with exception

CLI wrapper:

```bash
python -m Tools.egghunter.unified_builder_cli --strategy auto --tag W00T --badchars "\x00\x0a\x0d" --format python --print-egg
```

Production + CLI guide:
- `PRODUCTION.md`
