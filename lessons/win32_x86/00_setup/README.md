# 00 - Setup (Win32/x86 Lab)

Goal: get a known-good toolchain for building and debugging **32-bit** Windows binaries.

## Tooling (Windows VM)

- Visual Studio (or Build Tools) with:
  - MSVC v143 (or similar)
  - Windows 10/11 SDK
- WinDbg (modern) or WinDbg (classic)
- IDA Free (or Ghidra as alternative)
- Optional: x32dbg/x64dbg

## Confirm You Can Build x86

Use a "Developer Command Prompt for VS" (or `vcvarsall.bat x86`) and run:

```bat
cl
```

You should see a version banner (means `cl.exe` is on PATH).

## Quick Build Sanity Test

Build the program in `01_crash_basics/src/vuln_strcpy.c` as x86:

```bat
cd lessons\win32_x86\01_crash_basics\src
cl /nologo /W3 /Od /Zi /MT vuln_strcpy.c /link /OUT:vuln_strcpy_x86.exe
```

Check it is 32-bit:

```bat
dumpbin /headers vuln_strcpy_x86.exe | findstr /i machine
```

Expected: `machine (x86)`.

## WinDbg: Basic Launch

```bat
windbgx -o -g vuln_strcpy_x86.exe AAAA
```

If you use classic WinDbg, the executable name is usually `windbg.exe`.

## IDA Free: Basic Load

Open `vuln_strcpy_x86.exe`, let it analyze, then locate:

- `main`
- the vulnerable helper function (`vuln_copy`)

Focus on:

- stack frame allocation (local buffer size)
- the unsafe API call used to copy input into the buffer

## Anti-Footguns

- Keep each lesson binary in its own folder.
- Always save WinDbg output to a `.txt` file (copy/paste is fine).
- Treat every crash as data: record input length + exact bytes used.
