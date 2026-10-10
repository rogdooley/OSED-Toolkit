# OSED Reversing Labs

Three independent Windows x86 programs for black-box reverse-engineering practice with IDA Free.

## Build

On Windows, open a **Visual Studio 2022 Developer Command Prompt**, change to this directory, and run:

```bat
build.bat
build.bat validate
```

The batch build configures the Visual Studio generator with `-A Win32`, forcing PE32 x86 output regardless of the host prompt architecture. To build from Linux, install an i686 MinGW-w64 cross-compiler and run:

```text
make
make validate
```

Use `build.bat student-package` to assemble the student-only Windows bundle. Builds produce:

```text
dist/target01.exe
dist/target02.exe
dist/target03.exe
```

`target01.exe` and `target02.exe` are local TCP services. `target03.exe` accepts a file path.

Student-facing binaries, launch notes, and harmless sample input are assembled with `make student-package`.

## Validation status

The build and PE/runtime validation must be run on Windows. The local macOS checkout intentionally does not substitute a different architecture or claim Windows runtime results.
