# Native Badchar Target (Windows x86)

Deterministic regression target for debugger-assisted badchar workflows.

## Files

- `badchar_target.c`
- `build_msvc.bat`
- `build_mingw.bat`

## Behavior

- TCP server (default `127.0.0.1:9999`)
- Global buffers:
  - `char g_src[4096]`
  - `char g_dst[4096]`
- Copy boundary:
  - `strcpy(g_dst, g_src)`
- Modes:
  - `normal`: copy as-is
  - `truncate`: truncate at first `--trigger-byte`
  - `crash`: force crash when trigger byte appears
- Default lifecycle: persistent server loop
- Optional lifecycle:
  - `--oneshot`: exit after one client

## Build (MSVC, preferred for OSED workflows)

Open **x86 Native Tools Command Prompt for VS** and run:

```bat
build_msvc.bat
```

Produces `badchar_target.exe`.

## Build (MinGW-w64 x86)

```bat
build_mingw.bat
```

## Run

```bat
badchar_target.exe --host 127.0.0.1 --port 9999 --mode normal
```

```bat
badchar_target.exe --mode truncate --trigger-byte 0x0d
```

```bat
badchar_target.exe --mode crash --trigger-byte 0x0d --oneshot
```

## Manual cdb sanity check

1. Launch target under cdb:

```bat
cdb -o -g -G badchar_target.exe --host 127.0.0.1 --port 9999 --mode normal
```

2. Set breakpoint and continue:

```text
bp msvcrt!strcpy
g
```

3. Send a payload and verify:

```text
Breakpoint 0 hit
```

Then inspect call args:

- `poi(@esp+4)` => destination pointer (`g_dst`)
- `poi(@esp+8)` => source pointer (`g_src`)
