# Unified Egghunter: Production PoC + CLI

This guide covers two workflows:
- Production PoC integration in Python exploit scripts
- Command-line usage for fast hunter generation

Module files:
- `/home/roger/Documents/OSED/OSED-Toolkit/Tools/egghunter/unified_builder.py`
- `/home/roger/Documents/OSED/OSED-Toolkit/Tools/egghunter/unified_builder_cli.py`

## 1. Production PoC (Python)

```python
from Tools.egghunter import EgghunterBuilder, EgghunterConfig

cfg = EgghunterConfig(
    tag=b"W00T",                    # exactly 4 bytes
    badchars=b"\x00\x0a\x0d",
    debug=True,
    output_asm=False,
    target="win10_x86",            # win10_x86, win11_x86, server2012_x86+
)

builder = EgghunterBuilder(cfg)
hunter = builder.build(strategy="auto")  # seh_win10 / seh_classic / syscall / auto

egg = cfg.tag * 2
stage2 = egg + (b"\x90" * 32) + b"PAYLOAD"

print(f"hunter_len={len(hunter)}")
print(f"hunter = b\"{''.join(f'\\x{x:02x}' for x in hunter)}\"")
print(f"egg = b\"{''.join(f'\\x{x:02x}' for x in egg)}\"")
```

Notes:
- `build(...)` always returns raw `bytes`.
- Tag validation is strict: must be exactly 4 bytes.
- Syscall resolution priority is strict:
  1. `syscall_id_override`
  2. syscall table via `target`
  3. failure (no silent fallback)

## 2. CLI Usage

Run from repo root:

```bash
python -m Tools.egghunter.unified_builder_cli --strategy seh_win10 --tag W00T --badchars "\\x00\\x0a\\x0d"
```

### Common commands

Python-literal output (`hunter = b"\x.."`):

```bash
python -m Tools.egghunter.unified_builder_cli \
  --strategy auto \
  --tag W00T \
  --badchars "\\x00\\x0a\\x0d" \
  --target win10_x86 \
  --format python \
  --print-egg
```

Raw bytes to file:

```bash
python -m Tools.egghunter.unified_builder_cli \
  --strategy syscall \
  --tag W00T \
  --target win11_x86 \
  --format raw \
  --out hunter.bin
```

Force syscall override (highest priority):

```bash
python -m Tools.egghunter.unified_builder_cli \
  --strategy syscall \
  --tag W00T \
  --syscall-id 0x1C6 \
  --format escaped
```

Emit assembly template + debug lines:

```bash
python -m Tools.egghunter.unified_builder_cli \
  --strategy seh_win10 \
  --tag LOKI \
  --debug \
  --output-asm
```

## 3. Output Formats

- `--format python`: `hunter = b"\x.."`
- `--format escaped`: `\x..\x..`
- `--format hex`: plain hex string
- `--format raw`: binary bytes to stdout (use redirection or `--out`)

## 4. Operational Checks

Before deployment:
- Disassemble and single-step in WinDbg.
- Confirm no badchars in final hunter bytes.
- Confirm egg marker in memory is duplicated (`tag * 2`).
- Confirm selected strategy is stable under target constraints.
