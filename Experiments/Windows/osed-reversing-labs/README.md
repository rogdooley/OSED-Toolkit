# OSED Reversing Labs

Three independent Windows x86 programs for black-box reverse-engineering practice with IDA Free.

## Build

Install a MinGW-w64 **i686** toolchain, then run:

```text
make
make validate
```

`build.bat` provides the equivalent Windows command sequence. Builds produce:

```text
dist/target01.exe
dist/target02.exe
dist/target03.exe
```

`target01.exe` and `target02.exe` are local TCP services. `target03.exe` accepts a file path.

Student-facing binaries, launch notes, and harmless sample input are assembled with `make student-package`.

## Validation status

The build and PE/runtime validation must be run on a Windows x86 MinGW-w64 environment. The local macOS checkout intentionally does not substitute a different architecture or claim Windows runtime results.
