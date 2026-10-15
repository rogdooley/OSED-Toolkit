# OSED Bad-Character Discovery Lab

Windows x86 exercises for tracing candidate byte arrays through realistic input-processing paths with IDA Free and WinDbg.

The lab contains three loopback-only TCP targets (NET-01 through NET-03) and
three binary-file targets (FILE-01 through FILE-03). The TCP harness supports
`--probe` and `--overflow-context`; they retain the same challenge-specific
processing functions. `generate_file.py` constructs length-framed file records
without altering candidate bytes.

Build from a Visual Studio 2017, 2019, or 2022 Developer Command Prompt:

```bat
build\build.bat Release
```

The solution is Win32-only. Binaries are emitted to
`dist\\instructor\\Release\\` (or `Debug`). Host-side tests validate project
metadata and Python tooling; compilation, PE inspection, and WinDbg observations
require a Windows MSVC environment and are not claimed by this repository until
recorded in instructor material.
