# 03 - WinDbg Core Workflow (x86)

Goal: become fast and consistent in WinDbg for the tasks you will repeat constantly.

## Build Target (Windows, x86)

Reuse `01_crash_basics/src/vuln_strcpy.c` or any other small target you have.

## Launch Under WinDbg

Example:

```bat
windbgx -o -g vuln_strcpy_x86.exe AAAA
```

If the process exits normally, relaunch with a longer input to crash.

## Immediate Post-Crash Checklist

Run:

```
!analyze -v
r
r eip
.exr -1
.ecxr
k
dds esp L40
```

Questions to answer:

1. What exception code? (common: `c0000005`)
2. Is `EIP` a suspicious value that looks like your input?
3. Does the stack (`ESP`) contain your input bytes nearby?

## API Breakpoints (Understanding the Flow)

If your target uses `strcpy`, you may see it resolved in different CRTs.
Try these breakpoints (one may hit depending on build/runtime):

```
bp msvcrt!strcpy
bp ucrtbase!strcpy
bp kernel32!lstrcpyA
g
```

When a breakpoint hits:

```
kb
dd esp L20
da poi(esp+4)
```

This helps you validate where the user input pointer is coming from.

## Logging Output

```
.logopen /t crashlog.txt
!analyze -v
r
k
.logclose
```

Then triage from your host machine:

```bash
python -m Tools.crashtriage.cli.triage_crash -l 600 --input crashlog.txt
```

