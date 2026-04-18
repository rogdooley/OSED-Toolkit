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
