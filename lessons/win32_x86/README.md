# Win32/x86 Lessons (Crash Analysis First)

These lessons are designed for **Windows 10 x64 VM** running **32-bit (x86) user-mode binaries**.
They focus on:

- reliably reproducing crashes
- reading them in **WinDbg** (and optionally x32dbg/x64dbg)
- understanding the vulnerable code path in **IDA Free**
- measuring the effect of common compiler / linker mitigations

This intentionally stops at **crash triage and overwrite identification**. Use this only in your authorized lab.

## Directory Map

- `00_setup/` Environment setup, tooling, and build sanity checks
- `01_crash_basics/` First controllable crash + register/stack reading
- `02_fuzzing/` Minimal fuzzer + crash artifact logging
- `03_windbg_core/` WinDbg workflow: breakpoints, memory, stack, exception context
- `04_ida_core/` IDA Free workflow: finding the bug, stack frame sizing, unsafe APIs
- `05_mitigations/` Compile variants to observe /GS, /NXCOMPAT, /DYNAMICBASE effects
- `shared/` Common notes and WinDbg command snippets
- `tools/` Small helpers (Python) to generate inputs and parse/format bytes

## Recommended Workflow

1. Build the x86 binaries on your Windows machine (each lesson includes commands).
2. Run under WinDbg and capture the crash output.
3. Use the repo tool:
   - `python -m Tools.crashtriage.cli.triage_crash -l <pattern_len> --input crash.txt`
4. Use IDA Free to confirm the vulnerable buffer size and call chain.

## Notes

- Targets are Win32/x86 even though the VM is Win10 x64.
- Prefer building in **Release** with symbols (`/Zi`) when you want stable behavior.
